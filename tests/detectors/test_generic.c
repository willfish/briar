/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static size_t fail_size, fail_after, failed_allocations, fail_add_after;

/* Focused failures of actual compile/iteration/finding resources. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *value)
{
    size_t size = strlen(value) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name,
                           struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s)
{
    return (br_slice){(const unsigned char *)s, strlen(s)};
}

static void finding(const br_result *result, const char *expected)
{
    test_key_result(result, 7, expected, "key");
    CHECK(!result->verified && !result->verification_error);
}

static void expect(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify != 0, input, strlen(input));
        if (out.len != (expected ? 1u : 0u))
            fprintf(stderr, "input [%s]: got %zu findings, expected %u\n", input, out.len, expected ? 1u : 0u);
        CHECK(out.len == (expected ? 1u : 0u));
        if (expected) finding(&out.items[0], expected);
        br_results_clear(&out);
    }
    CHECK(!http.calls && !http.releases);
}

static void constructors(const br_detector **zero, const br_detector **configured)
{
    char *error = NULL;
    CHECK(br_generic_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_generic_new_init(NULL, NULL) == -1);
    const br_detector *d = (const br_detector *)1;
    fail_size = 2 * sizeof(void *); fail_after = 1;
    size_t before = failed_allocations;
    CHECK(br_generic_init(&d, &error) == -1 && !d && error);
    CHECK(!fail_after && failed_allocations == before + 1);
    free(error); error = NULL;
    CHECK(br_generic_init(zero, &error) == 0 && *zero && !error);

    /* Fail after at least one compile has succeeded; retry must not retain
     * partially initialized New() exclusions. */
    d = (const br_detector *)1;
    fail_size = 2 * sizeof(void *); fail_after = 3;
    before = failed_allocations;
    CHECK(br_generic_new_init(&d, &error) == -1 && !d && error);
    CHECK(!fail_after && failed_allocations == before + 1);
    free(error); error = NULL;
    CHECK(br_generic_new_init(configured, &error) == 0 && *configured && !error);
    CHECK(*zero != *configured);
    CHECK(br_generic_init(&d, &error) == 0 && d == *zero && !error);
    CHECK(br_generic_new_init(&d, &error) == 0 && d == *configured && !error);

    const char *const words[] = {"pass", "token", "cred", "secret", "key"};
    const br_detector *both[] = {*zero, *configured};
    for (size_t n = 0; n < 2; ++n) {
        d = both[n];
        CHECK(BR_ABI_REVISION == 1 && d->type == 7 && d->version == 0);
        CHECK(!strcmp(d->name, "Generic") && !strcmp(d->custom_name, ""));
        CHECK(!strcmp(d->description, "Generic secret key that may provide access to sensitive data or systems."));
        CHECK(d->nkeywords == 5);
        for (size_t i = 0; i < 5; ++i) CHECK(!strcmp(d->keywords[i], words[i]));
        CHECK(d->state && d->scan);
        CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
        CHECK(!d->clean && !d->clean_always && !d->false_positive);
        CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    }
}

static void extraction(const br_detector *d)
{
    static const char key[] = "Ab9!Cd8@Ef7$Gh6%Q";
    const char *formats[] = {"pass %s", "ToKeN %s", "cred %s", "secret %s", "key %s",
                             "bypasssuffix %s", "key\r\n%s", "key \xc3\xa9%s\xc3\xa9"};
    char input[320];
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        expect(d, input, key);
    }
    expect(d, key, NULL);
    expect(d, "key A!bcdefghijklmn", NULL); /* Fifteen bytes. */
    expect(d, "key a!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!z", "a!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!z");
    expect(d, "key A!bcdefgh\nijklmnop", NULL); /* Capture cannot cross LF. */
    expect(d, "key A!bcdefgh\rijklmnop", NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "key", 3);
        memset(input + 3, ' ', gap);
        memcpy(input + 3 + gap, key, sizeof(key));
        expect(d, input, gap == 40 ? key : NULL);
    }
    /* Only keyword folding is enabled: bytes in the capture stay original. */
    expect(d, "KEY aB!dEfGhIjKlMnOpQ", "aB!dEfGhIjKlMnOpQ");
    snprintf(input, sizeof(input), "key %s\nkey %s\nkey %s", key, key, key);
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, NULL, verify != 0, input, strlen(input));
        CHECK(out.len == 3);
        for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], key);
        br_results_clear(&out);
    }
    memcpy(input, "key\0", 4);
    memcpy(input + 4, key, sizeof(key));
    br_results out = test_scan(d, NULL, true, input, 4 + strlen(key));
    CHECK(out.len == 1); finding(&out.items[0], key); br_results_clear(&out);
    out = test_scan(d, NULL, true, NULL, 0);
    CHECK(!out.len); br_results_clear(&out);

    char capture[66];
    memset(capture, '_', 65); capture[65] = '\0';
    snprintf(input, sizeof(input), "key %s", capture);
    expect(d, input, NULL); /* Cannot truncate in the middle of a word. */
    capture[64] = '-'; capture[65] = '\0';
    char expected[65]; memcpy(expected, capture, 64); expected[64] = '\0';
    snprintf(input, sizeof(input), "key %s", capture);
    expect(d, input, expected);
}

static void trim_and_base64(const br_detector *d)
{
    const char *drop[] = {
        "key ABCDEFGHIJKLMNOP",       /* Standard alphabet, full groups. */
        "key ABCDEFGHIJKL+/MN",       /* Standard alphabet, arbitrary decoded bytes. */
    };
    for (size_t i = 0; i < sizeof(drop) / sizeof(drop[0]); ++i) expect(d, drop[i], NULL);
    expect(d, "key ABCDEFGHIJKLMNOPQ", "ABCDEFGHIJKLMNOPQ"); /* Unpadded length error. */
    expect(d, "key ABCDEFGHIJKLMNOPQR", "ABCDEFGHIJKLMNOPQR");
    expect(d, "key ABCDEFGHIJKLMN_Q", "ABCDEFGHIJKLMN_Q"); /* URL alphabet is not standard. */
    expect(d, "key ABCDEFGH=JKLMNOP", "ABCDEFGH=JKLMNOP"); /* Interior padding. */

    const char cut[] = "`\"'.,)(][}{";
    char capture[65], core[65], input[160];
    size_t ncut = strlen(cut), ncore = 64 - 2 * ncut;
    memset(core, 'a', ncore); core[1] = '!'; core[ncore] = '\0';
    memcpy(capture, cut, ncut); memcpy(capture + ncut, core, ncore);
    memcpy(capture + ncut + ncore, cut, ncut); capture[64] = '\0';
    /* Adjacent keyword and sentinel create boundaries at punctuation edges. */
    snprintf(input, sizeof(input), "token%sZ", capture);
    expect(d, input, core);
    memset(capture, '.', 64); capture[64] = '\0';
    snprintf(input, sizeof(input), "token%sZ", capture);
    expect(d, input, NULL); /* Trim to empty, successful DecodeString. */
    memset(capture, 'a', 64); capture[0] = '\\'; capture[1] = '!';
    capture[63] = '.'; capture[64] = '\0';
    memcpy(core, capture, 63); core[63] = '\0';
    snprintf(input, sizeof(input), "token%sZ", capture);
    expect(d, input, core); /* Backslash is not in the cutset. */

    /* Force a 64-byte capture ending in padding, not the sentinel. */
    memset(capture, 'A', 64); capture[62] = 'N'; capture[63] = '=';
    snprintf(input, sizeof(input), "key %sZ", capture);
    expect(d, input, NULL);
    capture[61] = 'N'; capture[62] = '=';
    snprintf(input, sizeof(input), "key %sZ", capture);
    expect(d, input, NULL);
    capture[61] = '=';
    snprintf(input, sizeof(input), "key %sZ", capture);
    memcpy(core, capture, sizeof(capture));
    expect(d, input, core); /* Three padding bytes is invalid. */
}

static void exclusions(const br_detector *zero, const br_detector *configured)
{
    const char *tokens[] = {
        "12345678-1234-abcd-9876-123456789abc",
        "12345678-1234-4abc-|123-123456789abc", /* Literal pipe in UUIDv4 class. */
        "a!prefix-ABC-1234-tailz",
        "a!color#abcdef-tailz",
        "https://example.invalid/a",
        "a!directory/file.txt",
        "a!AA:BB:CC:DD:EE:FFz",
        "a!date2025-10-28z",
        "a!prefix|1.2tailz", /* Literal pipe in version class. */
        "a!prefixV1.2tailz", /* Uppercase V must not match. */
        "a!prefix1.2.3-tailz",
        "a!prefix999.888.777.666z", /* No semantic IP validation. */
        "a!prefixxx:xx:xxz", /* Source hex class deliberately allows x. */
        "a!prefixfun(abc)z",
    };
    char input[200];
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i) {
        snprintf(input, sizeof(input), "key %s", tokens[i]);
        expect(zero, input, tokens[i]);
        expect(configured, input, i == 9 ? tokens[i] : NULL);
    }
    /* The function match depends on a closing containment char which trim
     * removes. Filtering must inspect the original capture, not its trim. */
    char capture[65], trimmed[65];
    memset(capture, 'a', 56); capture[1] = '!';
    memcpy(capture + 56, "fun(abc)", 8); capture[64] = '\0';
    memcpy(trimmed, capture, 63); trimmed[63] = '\0';
    snprintf(input, sizeof(input), "key %sZ", capture);
    expect(zero, input, trimmed);
    expect(configured, input, NULL);
    expect(configured, "key A!bcdefghijklmnop", "A!bcdefghijklmnop");
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0);
    CHECK(br_results_push(&out, &prior) == 0);
    return out;
}

static void rollback(const br_detector *zero, const br_detector *configured)
{
    const char input[] = "key Ab9!Cd8@Ef7$Gh6%Q\nkey Ab9!Cd8@Ef7$Gh6%Q";
    const br_detector *both[] = {zero, configured};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned();
        unsigned char *prior = out.items[0].raw.data;
        br_json *parts = out.items[0].secret_parts;
        char *error = NULL;
        fail_add_after = 2;
        CHECK(both[i]->scan(both[i], NULL, true, text(input), &out, &error) == -1 && error);
        CHECK(!fail_add_after && out.len == 1 && out.items[0].raw.data == prior && out.items[0].secret_parts == parts);
        test_key_result(&out.items[0], 17, "caller-owned", "key");
        free(error); br_results_clear(&out);

        out = caller_owned(); error = NULL;
        size_t capacity = out.cap; out.cap = 0; /* Real positive push guard. */
        CHECK(both[i]->scan(both[i], NULL, false, text(input), &out, &error) == -1 && error);
        out.cap = capacity;
        CHECK(out.len == 1); test_key_result(&out.items[0], 17, "caller-owned", "key");
        free(error); br_results_clear(&out);

        out = caller_owned(); error = NULL;
        fail_size = strlen("Ab9!Cd8@Ef7$Gh6%Q"); fail_after = 1;
        size_t before = failed_allocations;
        CHECK(both[i]->scan(both[i], NULL, true, text(input), &out, &error) == -1 && error);
        CHECK(!fail_after && failed_allocations == before + 1 && out.len == 1);
        test_key_result(&out.items[0], 17, "caller-owned", "key");
        free(error); br_results_clear(&out);
    }

    br_results out = caller_owned(); char *error = NULL;
    fail_size = sizeof(br_span); fail_after = 1;
    size_t before = failed_allocations;
    /* Iteration resources fail before the UUID's ordinary New() exclusion. */
    CHECK(configured->scan(configured, NULL, true,
                           text("key 12345678-1234-abcd-9876-123456789abc"), &out, &error) == -1 && error);
    CHECK(!fail_after && failed_allocations == before + 1 && out.len == 1);
    test_key_result(&out.items[0], 17, "caller-owned", "key");
    free(error); error = NULL;
    /* The shared iterator also owns a diagnostic for positive early stops. */
    fail_size = sizeof("regex callback aborted"); fail_after = 1;
    before = failed_allocations;
    CHECK(configured->scan(configured, NULL, true,
                           text("key 12345678-1234-abcd-9876-123456789abc"), &out, &error) == -1 && error);
    CHECK(!fail_after && failed_allocations == before + 1 && out.len == 1);
    test_key_result(&out.items[0], 17, "caller-owned", "key");
    free(error); error = NULL;
    CHECK(zero->scan(zero, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error);
    CHECK(out.len == 1); test_key_result(&out.items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *zero = NULL, *configured = NULL;
    constructors(&zero, &configured);
    extraction(zero); extraction(configured);
    trim_and_base64(zero); trim_and_base64(configured);
    exclusions(zero, configured);
    rollback(zero, configured);
    CHECK(!fail_after && !fail_add_after);
    return test_finish("Generic zero-value and New()");
}
