/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key1[49], key2[49];
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 48);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[49]; memcpy(copy, value, 48); copy[48] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_clockify_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 280 && detector->version == 0 && !strcmp(detector->name, "Clockify"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Clockify is a time tracking software. Clockify API keys can be used to access and modify time tracking data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clockify"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_clockify_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_clockify_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_clockify_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Clockify detector output"));
    free(error); CHECK(br_clockify_init(NULL, NULL) != 0);
    return detector;
}

static void unexpected_provider_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request;
    CHECK(!"keyed Clockify verification must be blocked BEFORE the injected send callback");
}

static void release_guarded(void *user, br_http_response *response)
{
    CHECK(response && !response->status && !response->headers && !response->nheaders);
    CHECK(!response->body.data && !response->body.len && !response->body_error);
    test_http_release(user, response);
}

static br_transport guarded_transport(test_http *http)
{
    br_transport transport = test_transport(http);
    transport.release = release_guarded;
    return transport;
}

static void check_unverified(const br_result *result, const char *key)
{
    test_key_result(result, 280, key, "key");
    CHECK(!result->verified && !result->verification_error);
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *key, size_t count)
{
    test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_unverified(&results.items[i], key);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[49];
    const struct { const char *format; size_t count; } cases[] = {
        {"clockify '%s'", 1}, {"CLOCKIFY=%s", 1}, {"cLoCkIfY\t%s", 1},
        {"preclockifysuffix %s", 1}, {"clockify\r\n%s\t", 1},
        {"%s", 0}, {"%s clockify", 0}, {"clock ify %s", 0}, {"clockify %.47s", 0},
        {"clockify A%s", 0}, {"clockify %sA", 0}, {"clockify _%s", 0}, {"clockify %s_", 0},
        {"clockify +%s/", 1}, {"clockify %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        expect_extraction(detector, input, strlen(input), key1, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "clockify", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key1, sizeof(key1));
        expect_extraction(detector, input, strlen(input), key1, gap == 40 ? 1 : 0);
    }
    const char forbidden[] = {'-', '_', '+', '/'};
    for (size_t i = 0; i < sizeof(forbidden); ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[24] = forbidden[i];
        snprintf(input, sizeof(input), "CLOCKIFY %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'Z', 48); changed[48] = '\0';
    snprintf(input, sizeof(input), "clockify %s", changed); expect_extraction(detector, input, strlen(input), changed, 1); /* No entropy/hex/Base64/JWT filtering or decoding. */
    memcpy(input, "clockify", 8); input[8] = '\0'; memcpy(input + 9, key1, 48);
    expect_extraction(detector, input, 57, key1, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_unkeyed_control(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(http->calls == 1 && ctx && ctx->transport);
    CHECK(request->detector_type == 0 && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://synthetic.invalid/control"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
}

static void unchanged_guard_with_unkeyed_control(void)
{
    test_http http = {.response = {.status = 200}, .inspect = inspect_unkeyed_control};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_http_request request = {.method = "GET", .url = "https://synthetic.invalid/control", .profile = BR_HTTP_SANE};
    br_http_response response = {0}; char *error = NULL;
    CHECK(br_http_send(&ctx, &request, &response, &error) == 0 && !error && response.status == 200);
    br_http_release(&ctx, &response); CHECK(http.calls == 1 && http.releases == 1);
    static const unsigned char keyed[] = "280:0123456789abcdef0123456789abcdef0123456789abcdef";
    CHECK(sizeof(keyed) - 1 == 52);
    request.dedup_key = (br_slice){keyed, sizeof(keyed) - 1}; http.calls = http.releases = 0;
    http.inspect = unexpected_provider_send; transport.release = release_guarded;
    CHECK(br_http_send(&ctx, &request, &response, &error) != 0 && error && !strcmp(error, "unsupported HTTP request coalescing"));
    CHECK(!http.calls && !response.status && !response.body_error); free(error);
    br_http_release(&ctx, &response); CHECK(!http.calls && http.releases == 1);
    /* Direct unkeyed HTTP control is NOT Clockify verification support. */
}

static void occurrences_and_blocked_verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "clockify %s\nCLOCKIFY %s\nclockify %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify < 2; ++verify) {
        br_results results = test_scan(detector, &ctx, verify != 0, input, strlen(input));
        CHECK(results.len == 3 && !http.calls && http.releases == (verify ? 3u : 0u));
        for (size_t i = 0; i < 3; ++i) check_unverified(&results.items[i], keys[i]);
        br_results_clear(&results);
    }
    http.releases = 0;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && http.releases == 3); /* No cache/consumption between scans. */
    for (size_t i = 0; i < 3; ++i) check_unverified(&results.items[i], keys[i]);
    br_results_clear(&results);
    http.releases = 0;
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_unverified(&results.items[i], keys[i]);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    CHECK(http.response.status == 200 && !http.response.body_error); /* Prepared success was NEVER consumed. */
}

static bool cancelled(void *user) { (void)user; return true; }
static void rejected_context_paths(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "clockify %s", key1);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send}; br_transport transport = guarded_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); check_unverified(&results.items[0], key1); br_results_clear(&results);
    }
    /* Rejection paths only, not coalesced cancellation/deadline, key lifetime,
     * header cloning, buffering/read-error promotion, replay or concurrency. */
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 280, (br_slice){(const unsigned char *)key1, 48}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Core failures need not be negative. */
    char input[256]; snprintf(input, sizeof(input), "clockify %s\nclockify %s\nclockify %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Clockify result"));
    CHECK(!fail_finding_after && !http.calls && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned")); free(error); error = NULL;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == 0 && !error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_unverified(&results.items[i], keys[i]);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 48, 0); test_secret(key2, 48, 17); key1[0] = 'A'; key1[47] = 'Z'; key2[24] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector); unchanged_guard_with_unkeyed_control(); occurrences_and_blocked_verification(detector);
    rejected_context_paths(detector); resource_rollback(detector);
    return test_finish("Clockify extraction + unchanged coalescing guard (verification unsupported)");
}
