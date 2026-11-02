/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SLICE(text) ((br_slice){ (const unsigned char *)(text), sizeof(text) - 1 })
#define REPLACEMENT "\xef\xbf\xbd"
#define KEY "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2"

static size_t assertions, cases, sends;
static const char *current;
#define CHECK(expr) do { ++assertions; if (!(expr)) { fprintf(stderr, "FAIL %s at %s:%d: %s\n", current, __FILE__, __LINE__, #expr); exit(1); } } while (0)

static void decode(const char *name, br_slice input, br_slice expected, bool borrowed)
{
    current = name;
    unsigned char *original = malloc(input.len ? input.len : 1);
    CHECK(original);
    if (input.len) memcpy(original, input.data, input.len);
    br_slice decoded = {0};
    br_bytes storage = {0};
    char *error = NULL;
    CHECK(!br_utf8_decode(input, &decoded, &storage, &error) && !error);
    CHECK(decoded.len == expected.len);
    CHECK(!decoded.len || !memcmp(decoded.data, expected.data, expected.len));
    CHECK(!input.len || !memcmp(input.data, original, input.len));
    if (borrowed) {
        CHECK(decoded.data == input.data && !storage.data && !storage.len);
    } else {
        CHECK(storage.data && decoded.data == storage.data && decoded.len == storage.len);
        CHECK(decoded.data != input.data);
    }
    free(storage.data);
    free(original);
    ++cases;
}

static int forbidden_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                           br_http_response *response, char **error)
{
    (void)user; (void)ctx; (void)request; (void)response; (void)error;
    ++sends;
    return 1;
}
static void no_release(void *user, br_http_response *response) { (void)user; (void)response; }

static void scan(const br_detector *detector, const char *name, br_slice input, size_t expected)
{
    current = name;
    br_slice decoded = {0};
    br_bytes storage = {0};
    char *error = NULL;
    CHECK(!br_utf8_decode(input, &decoded, &storage, &error) && !error);
    const br_transport transport = { NULL, forbidden_send, no_release };
    br_scan_ctx ctx = { .transport = &transport };
    br_results results = {0};
    CHECK(!detector->scan(detector, &ctx, false, decoded, &results, &error) && !error);
    CHECK(results.len == expected);
    for (size_t i = 0; i < results.len; ++i) {
        CHECK(results.items[i].raw.len == sizeof(KEY) - 1);
        CHECK(!memcmp(results.items[i].raw.data, KEY, sizeof(KEY) - 1));
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    CHECK(!sends);
    br_results_clear(&results);
    free(storage.data);
    ++cases;
}

static void gap(const br_detector *detector, const char *name, br_slice unit, size_t count, size_t expected)
{
    unsigned char input[256];
    size_t len = strlen("abyssale");
    memcpy(input, "abyssale", len);
    for (size_t i = 0; i < count; ++i) {
        memcpy(input + len, unit.data, unit.len);
        len += unit.len;
    }
    memcpy(input + len, KEY "\n", sizeof(KEY "\n") - 1);
    len += sizeof(KEY "\n") - 1;
    scan(detector, name, (br_slice){ input, len }, expected);
}

int main(void)
{
    decode("empty nil", (br_slice){0}, (br_slice){0}, true);
    decode("empty nonnil", SLICE(""), SLICE(""), true);
    decode("valid controls stay untouched", SLICE("A\0\t\n\r\f\x7fZ"), SLICE("A\0\t\n\r\f\x7fZ"), true);
    decode("valid multibyte scalars", SLICE("\xc3\xa9 \xe4\xb8\x96 \xf0\x9f\x98\x80"),
           SLICE("\xc3\xa9 \xe4\xb8\x96 \xf0\x9f\x98\x80"), true);
    decode("valid literal RuneError stays untouched", SLICE(REPLACEMENT), SLICE(REPLACEMENT), true);
    decode("one invalid byte", SLICE("\xff"), SLICE(REPLACEMENT), false);
    decode("invalid path replaces all ASCII controls", SLICE("A\xff\0\t\n\r\f\x7fZ"),
           SLICE("A" REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT "Z"), false);
    decode("overlong pair advances one byte", SLICE("A\xc0\x80Z"), SLICE("A" REPLACEMENT REPLACEMENT "Z"), false);
    decode("malformed two-byte tail", SLICE("A\xc2"), SLICE("A" REPLACEMENT), false);
    decode("malformed three-byte tail", SLICE("A\xe2\x82"), SLICE("A" REPLACEMENT REPLACEMENT), false);
    decode("malformed four-byte tail", SLICE("A\xf0\x9f\x92"), SLICE("A" REPLACEMENT REPLACEMENT REPLACEMENT), false);
    decode("surrogate encoding", SLICE("\xed\xa0\x80"), SLICE(REPLACEMENT REPLACEMENT REPLACEMENT), false);
    decode("out of Unicode range", SLICE("\xf4\x90\x80\x80"), SLICE(REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT), false);
    decode("valid scalars on invalid path", SLICE("\xc3\xa9 \xe4\xb8\x96 \xf0\x9f\x98\x80\xff"),
           SLICE("\xc3\xa9 \xe4\xb8\x96 \xf0\x9f\x98\x80" REPLACEMENT), false);
    decode("literal RuneError on invalid path advances one byte", SLICE(REPLACEMENT "\xff"),
           SLICE(REPLACEMENT REPLACEMENT REPLACEMENT REPLACEMENT), false);
    decode("ASCII inside malformed sequence survives", SLICE("x\xe2\x28\xa1"), SLICE("x" REPLACEMENT "(" REPLACEMENT), false);

    for (size_t at = 60; at < 76; ++at) {
        unsigned char sparse[128], repaired[130];
        memset(sparse, 'A', sizeof(sparse));
        sparse[at] = 0xc3; sparse[at + 1] = 0xa9;
        decode("ASCII words before and after a valid scalar", (br_slice){sparse, sizeof(sparse)},
               (br_slice){sparse, sizeof(sparse)}, true);
        sparse[at] = 0xff; sparse[at + 1] = 'A';
        memcpy(repaired, sparse, at);
        memcpy(repaired + at, REPLACEMENT, 3);
        memcpy(repaired + at + 3, sparse + at + 1, sizeof(sparse) - at - 1);
        decode("ASCII fast path cannot hide an invalid byte", (br_slice){sparse, sizeof(sparse)},
               (br_slice){repaired, sizeof(repaired)}, false);
    }

    current = "bounded input may expand to three times its original size";
    unsigned char *input = malloc(64 * 1024);
    CHECK(input);
    memset(input, 0xff, 64 * 1024);
    br_slice decoded = {0};
    br_bytes storage = {0};
    char *error = NULL;
    CHECK(!br_utf8_decode((br_slice){ input, 64 * 1024 }, &decoded, &storage, &error) && !error);
    CHECK(decoded.len == 3 * 64 * 1024 && decoded.data == storage.data);
    bool all_replacements = true;
    for (size_t i = 0; i < decoded.len; i += 3)
        if (memcmp(decoded.data + i, REPLACEMENT, 3)) all_replacements = false;
    CHECK(all_replacements);
    CHECK(input[0] == 0xff && input[64 * 1024 - 1] == 0xff);
    free(input); free(storage.data);
    ++cases;

    current = "invalid decoder arguments fail without output";
    CHECK(br_utf8_decode((br_slice){ NULL, 1 }, &decoded, &storage, &error) != 0 && error);
    CHECK(!decoded.data && !decoded.len && !storage.data && !storage.len);
    free(error); error = NULL;
    CHECK(br_utf8_decode(SLICE("text"), NULL, &storage, &error) != 0 && error);
    free(error); error = NULL;
    ++cases;

    current = "find descriptor without assuming registry size";
    const br_detector *const *registry = NULL;
    size_t count = 0;
    CHECK(!br_registry(&registry, &count, &error) && !error);
    const br_detector *detector = NULL;
    for (size_t i = 0; i < count; ++i)
        if (registry[i]->type == 239 && registry[i]->version == 0) detector = registry[i];
    CHECK(detector);
    scan(detector, "observed ASCII baseline", SLICE("abyssale " KEY "\n"), 1);
    scan(detector, "observed non-ASCII context", SLICE("\xc3\xa9 abyssale " KEY " \xe4\xb8\x96\xe7\x95\x8c\n"), 1);
    gap(detector, "observed 40 runes / 80 bytes", SLICE("\xc3\xa9"), 40, 1);
    gap(detector, "observed 41 runes / 82 bytes", SLICE("\xc3\xa9"), 41, 0);
    scan(detector, "observed invalid byte before keyword", SLICE("\xff" "abyssale " KEY "\n"), 1);
    scan(detector, "observed invalid byte after key", SLICE("abyssale " KEY "\xff\n"), 1);
    gap(detector, "observed 20 invalid pairs / 40 replacement runes", SLICE("\xc0\x80"), 20, 1);
    gap(detector, "observed 21 invalid pairs / 42 replacement runes", SLICE("\xc0\x80"), 21, 0);
    scan(detector, "key before malformed tail", SLICE("abyssale " KEY "\xf0\x9f\x92"), 1);
    scan(detector, "valid controls before key", SLICE("abyssale\0\t\n\r\x7f" KEY), 1);
    scan(detector, "invalid controls before key", SLICE("abyssale\0\t\n\r\x7f" KEY "\xff"), 1);
    printf("PLAIN UTF8: %zu cases, %zu assertions, 0 failures; no verification calls\n", cases, assertions);
    return 0;
}
