/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static size_t fail_finding_after;
typedef struct { const char *const *keys; size_t len; } expected_requests;

/* Target provider finding allocation, not the unified adapter/Do domain.
 * These captures are exactly 32 non-NUL ASCII bytes. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[33]; memcpy(copy, value, 32); copy[32] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_checklyhq_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 649 && detector->version == 0 && !strcmp(detector->name, "ChecklyHQ"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "ChecklyHQ is a monitoring service for API and browser checks. ChecklyHQ API keys can be used to access and manage these checks."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "checklyhq"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_checklyhq_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_checklyhq_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_checklyhq_init(NULL, &error) != 0 && error && !strcmp(error, "invalid ChecklyHQ detector output"));
    free(error);
    CHECK(br_checklyhq_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 649, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[33];
    const struct { const char *format; size_t count; } cases[] = {
        {"checklyhq '%s'", 1}, {"CHECKLYHQ=%s", 1}, {"cHeCkLyHq\t%s", 1},
        {"prechecklyhqsuffix %s", 1}, {"checklyhq\r\n%s\t", 1},
        {"%s", 0}, {"%s checklyhq", 0}, {"checkly hq %s", 0}, {"checklyhq %.31s", 0},
        {"checklyhq A%s", 0}, {"checklyhq %sA", 0}, {"checklyhq _%s", 0}, {"checklyhq %s_", 0},
        {"checklyhq +%s/", 1}, {"checklyhq %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        expect_extraction(detector, input, strlen(input), key1, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "checklyhq", 9); memset(input + 9, ':', gap); memcpy(input + 9 + gap, key1, sizeof(key1));
        expect_extraction(detector, input, strlen(input), key1, gap == 40 ? 1 : 0);
    }
    memcpy(changed, key1, sizeof(changed)); changed[16] = 'A';
    snprintf(input, sizeof(input), "CHECKLYHQ %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0); /* CI keyword only. */
    changed[16] = '-'; snprintf(input, sizeof(input), "checklyhq %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "checklyhq %s", changed); expect_extraction(detector, input, strlen(input), changed, 1); /* Lowercase alnum, not hex/entropy filtering. */
    memcpy(input, "checklyhq", 9); input[9] = '\0'; memcpy(input + 10, key1, 32);
    expect_extraction(detector, input, 42, key1, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.checklyhq.com/v1/checks"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 649);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *field = &request->headers[i];
        if (!strcmp(field->name, "Authorization")) {
            ++auth; CHECK(strlen(field->value) == 39 && !strncmp(field->value, "Bearer ", 7));
            CHECK(!strcmp(field->value + 7, expected->keys[http->calls - 1]));
        } else if (!strcmp(field->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(field->value, ctx->user_agent ? "TruffleHog checklyhq-test" : "TruffleHog"));
        } else CHECK(!"unexpected ChecklyHQ header (no Content-Type, Accept or logical Content-Length)");
    }
    CHECK(auth == 1 && agent == 1);
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "checklyhq %s\nCHECKLYHQ %s\nchecklyhq %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_requests expected = {keys, 3};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204, .body_error = "ignored read/close error"},
                          .send_rc = mode == 2 ? 1 : 0, .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (mode ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 649, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 649, keys[i], "key"); CHECK(!results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
}

static void status_and_do_errors(const br_detector *detector)
{
    char input[96], sensitive[160]; snprintf(input, sizeof(input), "checklyhq %s", key2);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read error with key %s", key2);
    const char *keys[] = {key2}; expected_requests expected = {keys, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true},
        {206, 0, NULL, true}, {299, 0, NULL, true}, {300, 0, NULL, false}, {400, 0, NULL, false},
        {401, 0, NULL, false}, {403, 0, NULL, false}, {429, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false},
        {200, 7, sensitive, false}, {200, 1, "context deadline exceeded", false},
        {200, 1, "unsupported: synthetic SANE transport", false}, {200, 1, NULL, false},
        {200, 1, "net/http: nil Context", false}, /* Do text does NOT identify a constructor failure. */
        {200, -1, "out of memory preparing native request", false}, /* Unified ABI send-domain partial gap. */
        {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "checklyhq-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); test_key_result(&results.items[0], 649, key2, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void suppressed_preflight_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "checklyhq %s", key1);
    const char *keys[] = {key1}; expected_requests expected = {keys, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); test_key_result(&results.items[0], 649, key1, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 649, (br_slice){(const unsigned char *)key1, 32}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Public core failures need not be negative. */
    char input[192]; snprintf(input, sizeof(input), "checklyhq %s\nchecklyhq %s\nchecklyhq %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_requests expected = {keys, 3};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating ChecklyHQ result"));
    CHECK(!fail_finding_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned")); free(error); error = NULL;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == 0 && !error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 649, keys[i], "key"); CHECK(results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 17); key1[31] = 'z'; key2[31] = 'g';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); status_and_do_errors(detector);
    suppressed_preflight_errors(detector); resource_rollback(detector);
    return test_finish("ChecklyHQ lowercase-alnum occurrences + bounded Bearer + suppressed Do errors");
}
