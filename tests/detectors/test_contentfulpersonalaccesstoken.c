/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "CFPAT-" "AbCdEfGhIj" "KlMnOpQrSt" "UvWxYz0123" "45_678-9_" "Z9_0";
static const char other[] = "CFPAT-" "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AAA";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Fail actual native capture/finding/redacted resources, without production
 * seams or heap auth copies. Non-failing allocations retain normal ownership. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 49 && strlen(other) == 49);
    CHECK(br_contentfulpersonalaccesstoken_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_contentfulpersonalaccesstoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_contentfulpersonalaccesstoken_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 103 && detector->version == 0 && !strcmp(detector->name, "ContentfulPersonalAccessToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Contentful is a content management system (CMS) that allows users to manage and deliver digital content. Contentful Personal Access Tokens can be used to access and modify this content."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "CFPAT-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    CHECK(result->detector_type == 103 && !result->detector_name);
    CHECK(result->raw.len == 49 && !memcmp(result->raw.data, expected, 49));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->extra_data && !result->structured_data);
    CHECK(result->redacted && strlen(result->redacted) == 7 && !memcmp(result->redacted, "...", 3));
    CHECK(!memcmp(result->redacted + 3, expected + 45, 4));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 49 && !memcmp(json_object_get_string(part), expected, 49));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[51];
    expect_one(detector, key, key); /* Direct pattern: no provider prefix or proximity rule. */
    expect_one(detector, other, other); /* No entropy/false-positive filter in FromData. */
    snprintf(input, sizeof(input), "contentful %s", key + 6); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); memcpy(changed, "cfpat-", 6); expect_one(detector, changed, NULL);
    memcpy(changed, key, sizeof(key)); changed[2] = 'p'; expect_one(detector, changed, NULL);
    memcpy(changed, key, sizeof(key)); changed[48] = '\0'; expect_one(detector, changed, NULL);
    snprintf(input, sizeof(input), "%sA", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "_%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "x%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%s_", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "-%s-", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "\"%s\"\r\n", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "CFPAT-%041d%s", 0, key); expect_one(detector, input, NULL); /* Word before C blocks it. */
    snprintf(input, sizeof(input), "CFPAT-%41s%s", "", key); expect_one(detector, input, key); /* No PrefixRegex 40-byte limit. */
    const char invalid[] = "+/.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[22] = invalid[i]; expect_one(detector, changed, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[48] = '_'; expect_one(detector, changed, changed);
    changed[48] = '-'; expect_one(detector, changed, NULL); /* Nonword '-' before end has no word boundary. */
    snprintf(input, sizeof(input), "%s!", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%s-", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%sZ", changed); expect_one(detector, input, changed); /* Captured '-' before a word DOES bound. */
    snprintf(input, sizeof(input), "%s_", changed); expect_one(detector, input, changed);
    snprintf(input, sizeof(input), "%s-", key); expect_one(detector, input, key); /* Extra allowed '-' stays outside the capture. */
    br_results empty = test_scan(detector, NULL, false, NULL, 0); CHECK(!empty.len); br_results_clear(&empty);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth;
} expected_requests;

static void auth_value(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 56 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, expected, 49) && value[56] == '\0');
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(ctx == expected->ctx && http->calls && http->calls <= expected->count);
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source scan-deferred close-only parity. */
    CHECK(request->detector_type == 103 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.contentful.com/organizations"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    auth_value(request->headers[0].value, expected->keys[http->calls - 1]);
    expected->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog contentful-test" : "TruffleHog"));
    /* Complete effective header set: no invented Content-Type, Accept or logical Content-Length. */
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected_requests *expected = http->user;
    /* br_http_send has freed its temporary header array; the provider's bounded
     * Authorization value must still be live, including on send failures. */
    auth_value(expected->borrowed_auth, expected->keys[http->calls - 1]);
    expected->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void occurrences_and_nil(const br_detector *detector)
{
    const char *keys[] = {key, other, key};
    unsigned char input[3 * 49 + 8]; size_t len = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, keys[i], 49); len += 49;
        input[len++] = '\0'; input[len++] = i == 1 ? '\r' : '\n';
    }
    input[len++] = 0xff; /* Full byte slices, not strlen-truncated input. */
    for (int verify = 0; verify <= 1; ++verify) {
        expected_requests expected = {.keys = keys, .count = 3};
        test_http http = {.response = {.status = 204}, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
        br_results results = test_scan(detector, &ctx, verify, input, len);
        CHECK(results.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls && !expected.borrowed_auth);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, len);
        CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char sensitive[192]; snprintf(sensitive, sizeof(sensitive), "synthetic Bearer %s repeated %s", key, key);
    const struct { int status, rc; const char *error; } cases[] = {
        {199, 0, NULL}, {200, 0, NULL}, {201, 0, NULL}, {204, 0, NULL}, {206, 0, NULL}, {299, 0, NULL},
        {300, 0, NULL}, {301, 0, NULL}, {401, 0, NULL}, {403, 0, NULL}, {429, 0, NULL}, {500, 0, NULL},
        {200, 1, "lookup synthetic.invalid: no such host"}, {200, -1, "context canceled"}, {200, 9, sensitive},
        {200, 1, "out of memory constructing HTTP headers"}, {200, 1, "net/http: nil Context"},
        {200, 1, "cannot redact ContentfulPersonalAccessToken result"}, {200, 1, NULL},
    };
    static const unsigned char body[] = {0xff, 0, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    const char *keys[] = {key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = keys, .count = 1};
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].rc, .send_error = cases[i].error, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "contentful-test"}; expected.ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, key, 49);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_auth);
        check_result(&results.items[0], key, cases[i].rc == 0 && cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_setup_errors(const br_detector *detector)
{
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : NULL,
                           .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results results = test_scan(detector, &ctx, true, key, 49);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
    br_json *part = NULL; CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[112]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    const char *keys[] = {key, other};
    const struct { size_t size, after; bool part; const char *error; bool reaches_first; } faults[] = {
        {0, 0, true, "cannot create ContentfulPersonalAccessToken result", true},
        {8, 2, false, "cannot redact ContentfulPersonalAccessToken result", true},
        {49, 2, false, "cannot create ContentfulPersonalAccessToken result", true},
        {2 * sizeof(br_span), 1, false, "out of memory iterating regex", false},
        {50, 2, false, "out of memory copying detector capture", false},
    };
    for (int mode = 0; mode < 3; ++mode) {
        expected_requests expected = {.keys = keys, .count = 2};
        test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error;
        br_json *parts = results.items[0].secret_parts;
        for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
            char *error = NULL; size_t failures = allocation_failures;
            http.calls = http.releases = 0;
            if (faults[i].part) fail_part_after = 2;
            else { fail_alloc_size = faults[i].size; fail_alloc_after = faults[i].after; }
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0,
                                    (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
            CHECK(rc == -1 && error && !strcmp(error, faults[i].error));
            CHECK(!fail_part_after && !fail_alloc_after && allocation_failures == failures + (faults[i].part ? 0u : 1u));
            CHECK(http.calls == (mode == 1 && faults[i].reaches_first ? 1u : 0u) && http.releases == http.calls && !expected.borrowed_auth);
            check_prior(&results, raw, prior_error, parts); free(error);
        }
        /* Positive ABI1 push rejection must also become fatal, never a skip.
         * Restore the deliberately rejected capacity before normal cleanup. */
        size_t capacity = results.cap; results.cap = 0; char *error = NULL;
        CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)key, 49}, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot append ContentfulPersonalAccessToken result"));
        check_prior(&results, raw, prior_error, parts); free(error); results.cap = capacity;
        CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, NULL) == 0);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    /* A failed invocation must not poison later scans. */
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other, false); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil(detector); statuses_and_errors(detector);
    shared_setup_errors(detector); resources_and_rollback(detector);
    return test_finish("ContentfulPersonalAccessToken");
}
