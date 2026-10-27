/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static size_t fail_size, fail_after, tracked_allocations;

/* Fail real Raw or regex-workspace allocations, never an invented auth seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size) {
        ++tracked_allocations;
        if (--fail_after == 0) return NULL;
    }
    return calloc(1, size);
}

static void make_key(char *key, size_t len)
{
    static const char alphabet[] = "aZ09_";
    CHECK(len >= 3 && len <= 168);
    memcpy(key, "ey", 2);
    for (size_t i = 2; i < len; ++i) key[i] = alphabet[i % (sizeof(alphabet) - 1)];
    if (len > 80) key[80] = '.';
    key[len - 1] = 'Q'; key[len] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_conversiontools_init(NULL, &error) == -1 && error && !strcmp(error, "invalid ConversionTools detector output")); free(error); error = NULL;
    CHECK(!br_conversiontools_init(&detector, &error) && detector && !error);
    CHECK(!br_conversiontools_init(&again, NULL) && again == detector);
    CHECK(detector->type == 769 && detector->version == 0 && !strcmp(detector->name, "ConversionTools") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "ConversionTools is a service used for various data conversion tasks. The API keys can be used to access and perform these tasks."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "conversiontools"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 769, key, "key");
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK((size_t)json_object_get_string_len(part) == strlen(key));
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    static size_t case_number;
    ++case_number;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    if (results.len != (expected ? 1u : 0u))
        fprintf(stderr, "extraction case %zu: %zu results, first length %zu\n", case_number, results.len, results.len ? results.items[0].raw.len : 0);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char minimum[160], maximum[168], changed[170], input[512];
    make_key(minimum, 159); make_key(maximum, 167);
    snprintf(input, sizeof(input), "conversiontools '%s'", minimum); expect_one(detector, input, minimum);
    snprintf(input, sizeof(input), "preCoNvErSiOnToOlSsuffix\r\n%s", maximum); expect_one(detector, input, maximum);
    expect_one(detector, minimum, NULL);
    snprintf(input, sizeof(input), "conversion tools %s", minimum); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "conversiontools%s", minimum); expect_one(detector, input, NULL); /* No starting word boundary. */
    snprintf(input, sizeof(input), "conversiontools _%s", minimum); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "conversiontools .%s!", minimum); expect_one(detector, input, minimum);
    snprintf(input, sizeof(input), "conversiontools %sX", maximum); expect_one(detector, input, NULL);
    make_key(changed, 158); snprintf(input, sizeof(input), "conversiontools %s", changed); expect_one(detector, input, NULL);
    make_key(changed, 168); snprintf(input, sizeof(input), "conversiontools %s", changed); expect_one(detector, input, NULL);
    changed[166] = '.'; snprintf(input, sizeof(input), "conversiontools %s", changed); changed[167] = '\0';
    expect_one(detector, input, changed); /* In-class period followed by a word also satisfies the final boundary. */
    memcpy(changed, minimum, sizeof(minimum)); changed[0] = 'E'; snprintf(input, sizeof(input), "CONVERSIONTOOLS %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, minimum, sizeof(minimum)); changed[1] = 'Y'; snprintf(input, sizeof(input), "CONVERSIONTOOLS %s", changed); expect_one(detector, input, NULL);
    const char invalid[] = {'-', '/', '+', '=', '\t', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, minimum, sizeof(minimum)); changed[80] = invalid[i];
        snprintf(input, sizeof(input), "conversiontools %s", changed); expect_one(detector, input, NULL);
    }
    memcpy(changed, "ey", 2); memset(changed + 2, '_', 161); changed[163] = '\0';
    snprintf(input, sizeof(input), "conversiontools %s", changed); expect_one(detector, input, changed); /* No JWT/entropy/word filtering. */
    snprintf(input, sizeof(input), "conversiontools %s.", minimum); expect_one(detector, input, minimum); /* Period is in-class, but trailing boundary backtracks. */
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "conversiontools%*s%s", gap, "", minimum); expect_one(detector, input, gap == 40 ? minimum : NULL);
    }
    snprintf(input, sizeof(input), "conversiontools %s %s", minimum, maximum); expect_one(detector, input, minimum); /* Whole-match non-overlap, no second keyword. */
    static const char prefix[] = "noise\0CONVERSIONTOOLS\r\n";
    memcpy(input, prefix, sizeof(prefix) - 1); memcpy(input + sizeof(prefix) - 1, maximum, sizeof(maximum) - 1);
    br_results results = test_scan(detector, NULL, false, input, sizeof(prefix) + sizeof(maximum) - 2);
    CHECK(results.len == 1); check_result(&results.items[0], maximum, false); br_results_clear(&results);
    results = test_scan(detector, NULL, false, NULL, 0); CHECK(!results.len); br_results_clear(&results);
}

typedef struct { const char *key, *send_error; int status, send_rc; } reply;
typedef struct {
    reply rows[3]; size_t count;
    const char *authorization, *suffix;
    const br_scan_ctx *expected_ctx;
} script;

static void check_authorization(const char *authorization, const char *key)
{
    CHECK(authorization && strlen(authorization) == 7 + strlen(key));
    CHECK(!memcmp(authorization, "Bearer ", 7) && !memcmp(authorization + 7, key, strlen(key)));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 769 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.conversiontools.io/v1/tasks"));
    static const char payload[] = "{  \"type\": \"convert.website_to_jpg\",  \"options\": {    \"url\": \"http://google.com\",    \"images\": \"yes\"  }}";
    CHECK(sizeof(payload) - 1 == 104 && request->body.len == 104 && !memcmp(request->body.data, payload, 104));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    steps->authorization = request->headers[1].value; check_authorization(steps->authorization, step->key);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, steps->suffix ? "TruffleHog offline-conversiontools" : "TruffleHog"));
    static const unsigned char body[] = {0xff, '\0', '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored body read failure"};
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->authorization) {
        CHECK(http->calls && http->calls <= steps->count);
        check_authorization(steps->authorization, steps->rows[http->calls - 1].key); /* Complete borrowed value remains live through release. */
        steps->authorization = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->authorization);
    return results;
}

static bool cancelled(void *user) { (void)user; return true; }

static void verification(const br_detector *detector)
{
    char key[160], other[168], input[768]; make_key(key, 159); make_key(other, 167);
    snprintf(input, sizeof(input), "conversiontools %s\nconversiontools %s\nconversiontools %s", key, other, key);
    const char *keys[] = {key, other, key}; script steps = {.count = 3, .suffix = "offline-conversiontools"};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = i == 1 ? 503 : 201};
    for (int verify = 0; verify <= 1; ++verify) {
        script none = {0}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i != 1);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    br_scan_ctx missing_transport = {0}; results = test_scan(detector, &missing_transport, true, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "conversiontools %s", other);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 301, 302, 307, 308, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = other, .status = statuses[i]}}};
        results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], other, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "context canceled", "context deadline exceeded", "no such host",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "cannot create ConversionTools result", NULL, other};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = other, .send_error = causes[i], .status = 200, .send_rc = i % 2 ? 1 : -1}}};
        results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], other, false); br_results_clear(&results);
    }
    /* Actual shared-send setup failures are suppressed, not constructor skips. */
    for (int mode = 0; mode < 3; ++mode) {
        steps = (script){0}; test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport};
        if (mode == 0) ctx.user_agent = "invalid\nagent";
        if (mode == 1) ctx.cancelled = cancelled;
        if (mode == 2) ctx.deadline_monotonic_ms = 1;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1); check_result(&results.items[0], other, false); br_results_clear(&results);
    }
    /* A failed send must not prevent a later occurrence from being verified. */
    snprintf(input, sizeof(input), "conversiontools %s\nconversiontools %s", key, other);
    steps = (script){.count = 2, .rows = {{.key = key, .send_error = "context canceled", .status = 200, .send_rc = 1}, {.key = other, .status = 204}}};
    results = run(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other, true); br_results_clear(&results);
}

static void resource_rollback(const br_detector *detector)
{
    char key[160], input[384]; make_key(key, 159);
    snprintf(input, sizeof(input), "conversiontools %s\nconversiontools %s", key, key);
    /* Includes shared positive regex-resource errors: all scan errors normalize
     * to -1, even with nil ctx or omitted error output; caller results survive. */
    const struct { bool verify, nil_ctx, no_error; size_t size, after, calls; } cases[] = {
        {true, false, false, 159, 2, 1}, {true, true, false, 159, 1, 0},
        {true, true, false, 159, 2, 0}, {false, false, true, 159, 2, 0},
        {true, true, false, 2 * sizeof(br_span), 1, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 2, .rows = {{.key = key, .status = 200}, {.key = key, .status = 201}}};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
        unsigned char *saved_raw = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        br_json *saved_parts = results.items[0].secret_parts;
        fail_size = cases[i].size; fail_after = cases[i].after; tracked_allocations = 0;
        int rc = detector->scan(detector, cases[i].nil_ctx ? NULL : &ctx, cases[i].verify,
                                (br_slice){(const unsigned char *)input, strlen(input)}, &results, cases[i].no_error ? NULL : &error);
        CHECK(rc == -1 && !fail_after && tracked_allocations == cases[i].after);
        CHECK(cases[i].no_error ? !error : error && !strcmp(error, cases[i].size == 159 ? "cannot create ConversionTools result" : "out of memory iterating regex"));
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !steps.authorization);
        CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].verified);
        CHECK(results.items[0].raw.data == saved_raw && results.items[0].raw.len == 5 && !memcmp(saved_raw, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned") && results.items[0].secret_parts == saved_parts);
        br_json *part = NULL; CHECK(json_object_object_get_ex(saved_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
        free(error); br_results_clear(&results);
    }
    script steps = {.count = 2, .rows = {{.key = key, .status = 200}, {.key = key, .status = 201}}};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); resource_rollback(detector);
    return test_finish("ConversionTools");
}
