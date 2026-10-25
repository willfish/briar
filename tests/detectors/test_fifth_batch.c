/* SPDX-License-Identifier: AGPL-3.0-only */
/* Synthetic acceptance derived from the pinned four detector implementations. */
#include "../../src/detectors/fifth_batch.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static size_t cases, assertions;
static const char *current_case = "setup";
#define CHECK(expr) do { \
    ++assertions; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s at %s:%d: %s\n", current_case, __FILE__, __LINE__, #expr); \
        fprintf(stderr, "%zu cases completed, 1 failure\n", cases); \
        exit(1); \
    } \
} while (0)

typedef struct {
    int32_t type;
    const char *name, *keyword, *description;
    size_t key_len;
} specification;
static const specification specs[] = {
    {1015, "AirtablePersonalAccessToken", "airtable",
     "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases.", 82},
    {498, "AirVisual", "airvisual",
     "AirVisual provides air quality information and monitoring. The API key allows access to various air quality data and services.", 36},
    {917, "Aiven", "aiven",
     "Aiven is a managed cloud service that provides various open-source data infrastructure services. Aiven API keys can be used to access and manage these services.", 372},
    {907, "Alchemy", "alchemy",
     "Alchemy is a blockchain development platform that provides a suite of tools and services for building and scaling decentralized applications. Alchemy API keys can be used to access these services.", 32},
};
static const char mixed[] = "b7C9d2E5f6G8h3J4k1M0n2P4q6R8s1T3u5V7w9X2y4Z6";

static void make_secret(const specification *spec, char out[512], size_t shift)
{
    if (spec->type == 1015) {
        memcpy(out, "pat", 3);
        for (size_t i = 0; i < 14; ++i) out[3 + i] = mixed[(i + shift) % (sizeof(mixed) - 1)];
        out[17] = '.';
        for (size_t i = 0; i < 64; ++i) out[18 + i] = "0123456789abcdef"[(i + shift) % 16];
        out[82] = '\0';
        return;
    }
    const char *alphabet = mixed;
    if (spec->type == 498) alphabet = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6";
    if (spec->type == 917) alphabet = "Bc7D9e2F5g6H8j3K4m1N0p2Q4r6S8t1U3v5W7x9Y2z4A6/+=";
    for (size_t i = 0; i < spec->key_len; ++i) out[i] = alphabet[(i + shift) % strlen(alphabet)];
    out[spec->key_len] = '\0';
    if (spec->type == 498) out[8] = out[13] = out[18] = out[23] = '-';
    if (spec->type == 907) out[10] = '_';
}

static void make_alcht(char out[512], size_t shift)
{
    memcpy(out, "alcht_", 6);
    for (size_t i = 0; i < 30; ++i) out[6 + i] = mixed[(i + shift) % (sizeof(mixed) - 1)];
    out[36] = '\0';
}

static char *copy_string(const char *text)
{
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    CHECK(copy != NULL);
    memcpy(copy, text, len);
    return copy;
}

static br_results scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const void *input, size_t len)
{
    br_results results = {0};
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, verify, (br_slice){input, len}, &results, &error) == 0);
    CHECK(error == NULL);
    return results;
}

static void check_result(const br_result *result, const specification *spec, const char *expected)
{
    CHECK(result->detector_type == spec->type);
    CHECK(result->detector_name == NULL && result->redacted == NULL);
    CHECK(result->raw.data != NULL && result->raw.len == strlen(expected));
    CHECK(memcmp(result->raw.data, expected, result->raw.len) == 0);
    CHECK(result->raw_v2.data == NULL && result->raw_v2.len == 0);
    CHECK(result->secret_parts != NULL && json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, spec->type == 1015 ? "token" : "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)strlen(expected));
    CHECK(strcmp(json_object_get_string(part), expected) == 0);
    CHECK(result->extra_data == NULL && result->structured_data == NULL);
    CHECK(!result->verification_from_cache);
    CHECK(result->primary_secret.data == NULL && result->primary_secret.len == 0);
    CHECK(result->primary_line == 0 && result->chunk_offset == 0 && !result->chunk_offset_set);
}

typedef struct {
    const specification *spec;
    const char *secret, *error, *body_error, *suffix;
    int status;
    bool send_fails;
    br_slice body;
    size_t calls, releases;
} fake_http;

static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    fake_http *fake = user;
    ++fake->calls;
    CHECK(ctx != NULL && ctx->transport != NULL && ctx->transport->user == fake);
    CHECK(strcmp(request->method, "GET") == 0);
    CHECK(request->detector_type == fake->spec->type);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->body.data == NULL && request->body.len == 0);
    CHECK(request->dedup_key.data == NULL && request->dedup_key.len == 0);
    char url[256];
    switch (fake->spec->type) {
    case 1015: snprintf(url, sizeof(url), "https://api.airtable.com/v0/meta/whoami"); break;
    case 498: snprintf(url, sizeof(url), "https://api.airvisual.com/v2/countries?key=%s", fake->secret); break;
    case 917: snprintf(url, sizeof(url), "https://api.aiven.io/v1/project"); break;
    default: snprintf(url, sizeof(url), "https://eth-mainnet.g.alchemy.com/v2/%s/getNFTs/?owner=vitalik.eth", fake->secret); break;
    }
    CHECK(strcmp(request->url, url) == 0);
    size_t nheaders = fake->spec->type == 498 ? 3 : fake->spec->type == 907 ? 1 : 2;
    CHECK(request->nheaders == nheaders);
    size_t agent = 0, accept = 0, auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcasecmp(header->name, "User-Agent")) {
            char expected[80];
            snprintf(expected, sizeof(expected), "TruffleHog%s%s", fake->suffix ? " " : "", fake->suffix ? fake->suffix : "");
            CHECK(strcmp(header->value, expected) == 0);
            ++agent;
        } else if (!strcasecmp(header->name, "Accept")) {
            CHECK(fake->spec->type == 498);
            CHECK(strcmp(header->value, "application/vnd.airvisual+json; version=3") == 0);
            ++accept;
        } else if (!strcasecmp(header->name, "Authorization")) {
            CHECK(fake->spec->type != 907);
            const char *prefix = fake->spec->type == 917 ? "aivenv1 " : "Bearer ";
            size_t prefix_len = strlen(prefix);
            CHECK(strncmp(header->value, prefix, prefix_len) == 0);
            CHECK(strlen(header->value) == prefix_len + strlen(fake->secret));
            CHECK(strcmp(header->value + prefix_len, fake->secret) == 0);
            ++auth;
        } else CHECK(!"unexpected request header");
    }
    CHECK(agent == 1 && accept == (fake->spec->type == 498 ? 1u : 0u));
    CHECK(auth == (fake->spec->type == 907 ? 0u : 1u));
    *response = (br_http_response){.status = fake->status, .body = fake->body, .body_error = fake->body_error};
    *error = fake->error ? copy_string(fake->error) : NULL;
    return fake->send_fails ? 1 : 0;
}

static void fake_release(void *user, br_http_response *response)
{
    CHECK(response != NULL);
    ++((fake_http *)user)->releases;
}

static void extraction(const br_detector *detector, const specification *spec,
                        const char *label, const void *input, size_t len,
                        const char *const *expected, size_t count)
{
    current_case = label;
    fake_http fake = {.spec = spec};
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan(detector, &ctx, false, input, len);
    CHECK(results.len == count);
    CHECK(fake.calls == 0 && fake.releases == 0);
    bool *seen = calloc(count ? count : 1, sizeof(*seen));
    CHECK(seen != NULL);
    for (size_t i = 0; i < results.len; ++i) {
        size_t j;
        for (j = 0; j < count; ++j)
            if (!seen[j] && results.items[i].raw.len == strlen(expected[j]) &&
                !memcmp(results.items[i].raw.data, expected[j], strlen(expected[j]))) break;
        CHECK(j < count); /* Upstream map iteration order is unspecified. */
        seen[j] = true;
        check_result(&results.items[i], spec, expected[j]);
        CHECK(!results.items[i].verified && results.items[i].verification_error == NULL);
    }
    free(seen);
    br_results_clear(&results);
    CHECK(results.items == NULL && results.len == 0 && results.cap == 0);
    ++cases;
}

static void extraction_tests(const br_detector *detector, const specification *spec)
{
    char key[512], second[512], changed[512], input[4096];
    make_secret(spec, key, 0);
    make_secret(spec, second, 9);
    const char *one[] = {key}, *two[] = {key, second};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    snprintf(input, sizeof(input), "%s %s", spec->keyword, key);
    EXTRACT("baseline exact capture and full result fields", 1, one);
    extraction(detector, spec, "empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("local extraction requires the provider prefix", 0, NULL);
    snprintf(input, sizeof(input), "%s %s", key, spec->keyword);
    EXTRACT("keyword after the value is insufficient", 0, NULL);
    char prefix[32];
    for (size_t i = 0; i <= strlen(spec->keyword); ++i)
        prefix[i] = (char)toupper((unsigned char)spec->keyword[i]);
    snprintf(input, sizeof(input), "pre%ssuffix:%s", prefix, key);
    EXTRACT("prefix is scoped case-insensitive with no word boundary", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen(spec->keyword);
        memcpy(input, spec->keyword, at);
        memset(input + at, ' ', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key);
        EXTRACT("exact prefix distance 40/41", gap == 40 ? 1 : 0, one);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen(spec->keyword);
        memcpy(input, spec->keyword, at);
        for (size_t i = 0; i < gap; ++i) { input[at++] = (char)0xc3; input[at++] = (char)0xa9; }
        snprintf(input + at, sizeof(input) - at, "%s", key);
        EXTRACT("prefix distance counts runes, not bytes", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "%s\r\n%s", spec->keyword, key);
    EXTRACT("prefix spans CR/LF", 1, one);
    snprintf(input, sizeof(input), "%s%s", spec->keyword, key);
    EXTRACT("Aiven alone has no leading capture boundary", spec->type == 917 ? 1 : 0, one);
    snprintf(input, sizeof(input), "%s _%s", spec->keyword, key);
    EXTRACT("exact left underscore boundary behavior", spec->type == 917 ? 1 : 0, one);
    snprintf(input, sizeof(input), "%s %s_", spec->keyword, key);
    EXTRACT("exact right underscore boundary behavior", spec->type == 917 ? 1 : 0, one);
    snprintf(input, sizeof(input), "%s %.*s", spec->keyword, (int)spec->key_len - 1, key);
    EXTRACT("short capture rejected", 0, NULL);
    snprintf(input, sizeof(input), "%s %sX", spec->keyword, key);
    EXTRACT("Aiven truncates longer allowed runs to first 372 bytes", spec->type == 917 ? 1 : 0, one);
    strcpy(changed, key);
    changed[spec->key_len / 2] = '!';
    snprintf(input, sizeof(input), "%s %s", spec->keyword, changed);
    EXTRACT("capture alphabet is not a generic token fallback", 0, NULL);
    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, key);
    EXTRACT("unique-match map removes duplicate occurrences", 1, one);
    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, second);
    EXTRACT("distinct matches are not cleaned inside the detector", 2, two);
    size_t at = strlen(spec->keyword);
    memcpy(input, spec->keyword, at);
    input[at++] = '\0';
    at += (size_t)snprintf(input + at, sizeof(input) - at, "%s", key);
    extraction(detector, spec, "binary NUL separator", input, at, one, 1);
    if (spec->type == 1015) {
        strcpy(changed, key);
        changed[0] = 'P';
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT literal pat prefix remains lowercase", 0, NULL);
        strcpy(changed, key);
        for (size_t i = 3; i < 17; ++i) changed[i] = (char)toupper((unsigned char)changed[i]);
        const char *upper_head[] = {changed};
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT head permits uppercase ASCII alphanumeric", 1, upper_head);
        changed[5] = '_';
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT head excludes underscore", 0, NULL);
        strcpy(changed, key);
        changed[3] = (char)0xc3;
        changed[4] = (char)0xa9;
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT POSIX alnum class stays ASCII", 0, NULL);
        strcpy(changed, key);
        changed[17] = ':';
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT separator is a literal dot", 0, NULL);
        strcpy(changed, key);
        changed[24] = 'A';
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT tail permits only lowercase hex", 0, NULL);
        changed[24] = 'g';
        snprintf(input, sizeof(input), "airtable %s", changed);
        EXTRACT("PAT tail is hex rather than all lowercase letters", 0, NULL);
        snprintf(input, sizeof(input), "airtable pat%.*s.%s", 13, key + 3, key + 18);
        EXTRACT("PAT head must have 14 characters", 0, NULL);
        snprintf(input, sizeof(input), "airtable pat%.*sZ.%s", 14, key + 3, key + 18);
        EXTRACT("PAT long head rejected", 0, NULL);
        memcpy(changed, "pat", 3);
        memset(changed + 3, 'a', 14);
        changed[17] = '.';
        memset(changed + 18, 'a', 64);
        changed[82] = '\0';
    } else if (spec->type == 498) {
        strcpy(changed, key);
        changed[0] = 'B';
        snprintf(input, sizeof(input), "airvisual %s", changed);
        EXTRACT("AirVisual capture is case-sensitive despite prefix case folding", 0, NULL);
        strcpy(changed, key);
        changed[0] = '-';
        const char *hyphen[] = {changed};
        snprintf(input, sizeof(input), "airvisual%s", changed);
        EXTRACT("AirVisual initial hyphen can satisfy a word-to-nonword boundary", 1, hyphen);
        snprintf(input, sizeof(input), "airvisual %s", changed);
        EXTRACT("AirVisual initial hyphen after space has no boundary", 0, NULL);
        strcpy(changed, key);
        changed[35] = '-';
        snprintf(input, sizeof(input), "airvisual %s", changed);
        EXTRACT("AirVisual final hyphen before nonword has no boundary", 0, NULL);
        snprintf(input, sizeof(input), "airvisual %sQ", changed);
        EXTRACT("AirVisual final hyphen before word satisfies the boundary", 1, hyphen);
        changed[0] = 'b';
        memset(changed + 1, '-', 34);
        changed[35] = '7';
        const char *not_uuid[] = {changed};
        snprintf(input, sizeof(input), "airvisual %s", changed);
        EXTRACT("AirVisual validates its class and length, not UUID syntax", 1, not_uuid);
        memset(changed, 'a', 36);
        changed[36] = '\0';
    } else if (spec->type == 917) {
        changed[0] = 'R';
        memcpy(changed + 1, key, 371);
        changed[372] = '\0';
        const char *shifted[] = {changed};
        snprintf(input, sizeof(input), "aiven R%s", key);
        EXTRACT("Aiven captures from the earliest allowed byte without word boundaries", 1, shifted);
        snprintf(input, sizeof(input), "aiven %s%s", key, second);
        EXTRACT("Aiven does not reuse one provider prefix for adjacent keys", 1, one);
        strcpy(changed, key);
        changed[123] = '_';
        snprintf(input, sizeof(input), "aiven %s", changed);
        EXTRACT("Aiven is not the URL-safe Base64 alphabet", 0, NULL);
        changed[123] = '-';
        snprintf(input, sizeof(input), "aiven %s", changed);
        EXTRACT("Aiven excludes hyphens", 0, NULL);
        memset(changed, '=', 372);
        changed[372] = '\0';
    } else {
        strcpy(changed, key);
        changed[0] = changed[31] = '_';
        const char *underscores[] = {changed};
        snprintf(input, sizeof(input), "alchemy %s", changed);
        EXTRACT("Alchemy old keys allow underscores at both boundaries", 1, underscores);
        char alcht[512];
        make_alcht(alcht, 0);
        const char *new_key[] = {alcht};
        snprintf(input, sizeof(input), "alchemy %s", alcht);
        EXTRACT("Alchemy alcht_ alternative captures all 36 bytes", 1, new_key);
        snprintf(input, sizeof(input), "%s", alcht);
        EXTRACT("Alchemy alcht_ prefilter keyword does not replace its regex provider prefix", 0, NULL);
        snprintf(input, sizeof(input), "alcht_ %s", alcht);
        EXTRACT("Alchemy prefix regex does not include the alternate prefilter keyword", 0, NULL);
        snprintf(input, sizeof(input), "ALCHEMY %s", alcht);
        EXTRACT("Alchemy provider prefix remains scoped case-insensitive", 1, new_key);
        memcpy(alcht, "ALCHT_", 6);
        snprintf(input, sizeof(input), "alchemy %s", alcht);
        EXTRACT("Alchemy alcht_ literal is case-sensitive", 0, NULL);
        make_alcht(alcht, 0);
        alcht[12] = '_';
        snprintf(input, sizeof(input), "alchemy %s", alcht);
        EXTRACT("Alchemy new payload alphabet excludes underscore", 0, NULL);
        make_alcht(alcht, 0);
        snprintf(input, sizeof(input), "alchemy %.*s", 35, alcht);
        EXTRACT("Alchemy new payload must have 30 characters", 0, NULL);
        snprintf(input, sizeof(input), "alchemy %sX", alcht);
        EXTRACT("Alchemy new payload right boundary", 0, NULL);
        snprintf(input, sizeof(input), "alchemy %s\nalchemy %s\nalchemy %s", key, alcht, alcht);
        const char *both[] = {key, alcht};
        EXTRACT("Alchemy deduplicates each identity while retaining both token forms", 2, both);
        memset(changed, '_', 32);
        changed[32] = '\0';
    }
    const char *low[] = {changed};
    snprintf(input, sizeof(input), "%s %s", spec->keyword, changed);
    EXTRACT("no detector-local entropy, decoding or false-positive filtering", 1, low);
#undef EXTRACT
    printf("PASS %s extraction/unique matches/exact prefix and capture semantics\n", spec->name);
}

static void verification_case(const br_detector *detector, const specification *spec,
                               const char *label, fake_http *fake, const char *override,
                               bool verified, const char *expected_error)
{
    current_case = label;
    char key[512], input[2048];
    make_secret(spec, key, 0);
    const char *secret = override ? override : key;
    fake->spec = spec;
    fake->secret = secret;
    fake->calls = fake->releases = 0;
    snprintf(input, sizeof(input), "%s %s", spec->keyword, secret);
    br_transport transport = {fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    br_results results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && fake->calls == 1 && fake->releases == 1);
    check_result(&results.items[0], spec, secret);
    CHECK(results.items[0].verified == verified);
    if (expected_error) {
        CHECK(results.items[0].verification_error != NULL);
        CHECK(strcmp(results.items[0].verification_error, expected_error) == 0);
    } else CHECK(results.items[0].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
}

static bool always_cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void verification_tests(const br_detector *detector, const specification *spec)
{
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', 'J', 'S', 'O', 'N'};
    fake_http fake = {.status = 200, .body = {body, sizeof(body)}};
    verification_case(detector, spec, "exact request and successful status, not JSON parsing", &fake, NULL, true, NULL);
    fake.body = (br_slice){NULL, 0};
    verification_case(detector, spec, "empty body does not alter success", &fake, NULL, true, NULL);
    fake.body = (br_slice){body, sizeof(body)};
    fake.body_error = "ignored body read/drain failure";
    fake.suffix = "fifth-batch-tests";
    const int statuses[] = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake.status = statuses[i];
        bool success = fake.status == 200;
        bool rejected = fake.status == 401 || ((spec->type == 498 || spec->type == 917) && fake.status == 403);
        char error[80];
        snprintf(error, sizeof(error), spec->type == 1015 || spec->type == 907 ?
                 "unexpected HTTP response status %d" : "unexpected status code: %d", fake.status);
        verification_case(detector, spec, "all status branches ignore body read errors", &fake, NULL,
                          success, success || rejected ? NULL : error);
    }
    fake.status = 200;
    fake.body_error = NULL;
    fake.send_fails = true;
    const char *errors[] = {"context deadline exceeded", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fake.error = errors[i];
        verification_case(detector, spec, "failed send is indeterminate despite response status 200", &fake, NULL,
                          false, fake.error ? fake.error : "HTTP transport failed");
    }
    char key[512], sensitive_error[2 * sizeof(key) + 32];
    make_secret(spec, key, 0);
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s failed: %s", key, key);
    fake.error = sensitive_error;
    bool redact = spec->type == 1015 || spec->type == 907;
    verification_case(detector, spec, "upstream redaction arguments and every token occurrence", &fake, NULL, false,
                      redact ? "request [REDACTED] failed: [REDACTED]" : sensitive_error);
    fake.send_fails = false;
    fake.error = NULL;
    if (spec->type == 907) {
        char new_key[512];
        make_alcht(new_key, 3);
        verification_case(detector, spec, "Alchemy new token is not truncated in verification URL", &fake, new_key, true, NULL);
        snprintf(sensitive_error, sizeof(sensitive_error), "request %s failed: %s", new_key, new_key);
        fake.send_fails = true;
        fake.error = sensitive_error;
        verification_case(detector, spec, "Alchemy redacts the whole new 36-byte capture", &fake, new_key, false,
                          "request [REDACTED] failed: [REDACTED]");
        fake.send_fails = false;
        fake.error = NULL;
    }
    char input[2048];
    snprintf(input, sizeof(input), "%s %s", spec->keyword, key);
    for (int mode = 0; mode < 3; ++mode) {
        current_case = "missing transport, cancellation and expired deadline retain candidates";
        fake.calls = fake.releases = 0;
        size_t checks = 0;
        br_transport transport = {&fake, fake_send, fake_release};
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
                           .cancelled = mode == 1 ? always_cancelled : NULL, .cancel_user = &checks,
                           .deadline_monotonic_ms = mode == 2 ? 1 : 0};
        br_results results = scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error != NULL && results.items[0].verification_error[0]);
        CHECK(fake.calls == 0 && fake.releases == (mode == 0 ? 0u : 1u));
        CHECK(mode != 1 || checks > 0);
        check_result(&results.items[0], spec, key);
        br_results_clear(&results);
        ++cases;
    }
    current_case = "unique-match map verifies duplicate occurrences once";
    fake.secret = key;
    fake.calls = fake.releases = 0;
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake.suffix};
    char duplicate[4096];
    snprintf(duplicate, sizeof(duplicate), "%s\n%s", input, input);
    br_results results = scan(detector, &ctx, true, duplicate, strlen(duplicate));
    CHECK(results.len == 1 && fake.calls == 1 && fake.releases == 1);
    CHECK(results.items[0].verified && results.items[0].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
    current_case = "no match means no verification request";
    fake.calls = fake.releases = 0;
    results = scan(detector, &ctx, true, "unrelated", strlen("unrelated"));
    CHECK(results.len == 0 && fake.calls == 0 && fake.releases == 0);
    br_results_clear(&results);
    ++cases;
    printf("PASS %s verification/request/status/body/error branches\n", spec->name);
}

static void descriptor_tests(const br_detector *const *detectors, size_t count)
{
    current_case = "fifth-batch exact metadata/defaults/versions/capabilities";
    CHECK(BR_ABI_REVISION == 1 && count == 4);
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        CHECK(detector->type == specs[i].type && detector->version == 0);
        CHECK(strcmp(detector->name, specs[i].name) == 0);
        CHECK(strcmp(detector->description, specs[i].description) == 0);
        CHECK(detector->custom_name != NULL && detector->custom_name[0] == '\0');
        CHECK(detector->nkeywords == (specs[i].type == 907 ? 2u : 1u));
        CHECK(strcmp(detector->keywords[0], specs[i].keyword) == 0);
        if (specs[i].type == 907) CHECK(strcmp(detector->keywords[1], "alcht_") == 0);
        CHECK(detector->state != NULL && detector->scan != NULL);
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
        CHECK(detector->clean == NULL && !detector->clean_always && detector->false_positive == NULL);
        CHECK(detector->validate_endpoints == NULL && detector->cloud_endpoint == NULL);
        CHECK(br_fifth_batch_is_default(detector));
        br_detector copied = *detector;
        CHECK(br_fifth_batch_is_default(&copied));
        copied.version = 1;
        CHECK(!br_fifth_batch_is_default(&copied));
        copied.version = 0;
        copied.custom_name = "custom";
        CHECK(!br_fifth_batch_is_default(&copied));
    }
    br_detector unknown = {.type = 99999};
    CHECK(!br_fifth_batch_is_default(&unknown) && !br_fifth_batch_is_default(NULL));
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    char *error = NULL;
    CHECK(br_fifth_batch(&again, &nagain, &error) == 0 && error == NULL);
    CHECK(again == detectors && nagain == count);
    CHECK(br_fifth_batch(NULL, &nagain, &error) != 0 && error != NULL && nagain == 0);
    free(error);
    error = NULL;
    CHECK(br_fifth_batch(&again, NULL, &error) != 0 && error != NULL && again == NULL);
    free(error);
    ++cases;
    printf("PASS fifth-batch descriptors: pinned order, unversioned/default-enabled, exact Alchemy keyword OR\n");
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_fifth_batch(&detectors, &count, &error) == 0 && error == NULL);
    descriptor_tests(detectors, count);
    for (size_t i = 0; i < count; ++i) {
        extraction_tests(detectors[i], &specs[i]);
        verification_tests(detectors[i], &specs[i]);
    }
    printf("PASS: %zu fifth-batch cases, %zu assertions, 0 failures; synthetic injected transport only\n", cases, assertions);
    return 0;
}
