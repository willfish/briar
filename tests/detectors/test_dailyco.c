/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_dailyco_init(const br_detector **out, char **error);

static size_t fail_size, fail_alloc_after, fail_part_after;

/* Fail genuine resources, not an invented heap Bearer/header allocation. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void make_key(char key[65], size_t shift)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; ++i) key[i] = hex[(i + shift) % 16];
    key[64] = '\0';
}

static const br_detector *descriptor(void)
{
    /* Pinned defaults.go:1124 comments out &dailyco.Scanner{}. Test the direct
     * native factory, not a positive CLI/default/include-selector oracle. */
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_dailyco_init(NULL, &error) == -1 && error && !strcmp(error, "invalid DailyCO detector output"));
    free(error); error = NULL;
    fail_size = sizeof("(?i:daily)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_dailyco_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_dailyco_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dailyco_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 585 && detector->version == 0 && !strcmp(detector->name, "DailyCO"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DailyCO is a video calling service that provides APIs to create and manage video calls. The API keys can be used to access and control these video call services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "daily"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_dailyco_init(NULL, NULL) == -1);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 585, key, "key");
    CHECK(result->raw.len == 64 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_get_string_len(part) == 64);
}

static void expect_one(const br_detector *detector, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char key[65], changed[65], input[512]; make_key(key, 0);
    const struct { const char *format; bool match; } cases[] = {
        {"daily '%s'", true}, {"preDaIlYsuffix\r\n%s", true}, {"DAILY %s", true},
        {"dailyco %s", true}, {"daily .%s!", true}, {"%s", false},
        {"%s daily", false}, {"dai ly %s", false}, {"co %s", false},
        {"daily%s", false}, {"daily _%s", false}, {"daily %s_", false},
        {"daily %s0", false}, {"daily %.63s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_one(detector, input, strlen(input), cases[i].match ? key : NULL);
    }
    const char invalid[] = {'A', 'F', 'g', 'z', '_', '-', '/', '=', ' ', '\t', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed)); changed[31] = invalid[i];
        snprintf(input, sizeof(input), "DAILY %s", changed); expect_one(detector, input, strlen(input), NULL);
    }
    memset(changed, '0', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "daily %s", changed);
    expect_one(detector, input, strlen(input), changed); /* No entropy or detector-local false-positive filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "daily", 5); memset(input + 5, '.', gap); memcpy(input + 5 + gap, key, sizeof(key));
        expect_one(detector, input, strlen(input), gap == 40 ? key : NULL);
        size_t at = 5;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
        memcpy(input + at, key, sizeof(key)); expect_one(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "daily %s %s", key, key);
    expect_one(detector, input, strlen(input), key); /* Whole matches consume the keyword, too. */
    static const unsigned char prefix[] = "bad\xff\0daily\0";
    memcpy(input, prefix, sizeof(prefix) - 1); memcpy(input + sizeof(prefix) - 1, key, 64);
    expect_one(detector, input, sizeof(prefix) - 1 + 64, key); /* No global UTF-8 guard or C-string truncation. */
    snprintf(input, sizeof(input), "daily \xc3\xa9%s\xc3\xa9", key);
    expect_one(detector, input, strlen(input), key); /* ASCII word boundaries. */
    expect_one(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *error; int status, rc; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *ctx; const char *borrowed_auth; } script;

static void check_authorization(const char *authorization, const char *key)
{
    CHECK(authorization && strlen(authorization) == 71);
    CHECK(!memcmp(authorization, "Bearer ", 7));
    CHECK(!memcmp(authorization + 7, key, 65)); /* Includes the complete key and trailing NUL. */
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->ctx);
    CHECK(request->detector_type == 585 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.daily.co/v1/rooms"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* No Content-Type, Accept, API-key header or invented Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    steps->borrowed_auth = request->headers[0].value; check_authorization(steps->borrowed_auth, steps->rows[at].key);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") &&
        !strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog offline-dailyco" : "TruffleHog"));
    static const unsigned char invalid_body[] = {'{', '?', '\0', 0xff};
    http->response = (br_http_response){.status = steps->rows[at].status,
        .body = {invalid_body, sizeof(invalid_body)}, .body_error = "ignored body read error"};
    http->send_rc = steps->rows[at].rc; http->send_error = steps->rows[at].error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->borrowed_auth) {
        CHECK(http->calls && http->calls <= steps->count);
        check_authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key); /* Stack Bearer is live through release. */
        steps->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport scripted_transport(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps, bool suffix)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = scripted_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = suffix ? "offline-dailyco" : NULL}; steps->ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    return results;
}

static void verification(const br_detector *detector)
{
    char key[65], other[65], input[384]; make_key(key, 0); make_key(other, 7);
    snprintf(input, sizeof(input), "daily %s\ndaily %s\ndaily %s", key, other, key);
    const char *keys[] = {key, other, key};
    for (int verify = 0; verify <= 1; ++verify) {
        script steps = {.count = verify ? 3 : 0, .rows = {{.key = key, .status = 200}, {.key = other, .status = 403}, {.key = key, .status = 299}}};
        br_results results = run(detector, input, verify, &steps, true); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i != 1);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "daily %s", key);
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = statuses[i]}}};
        results = run(detector, input, true, &steps, false); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"context canceled", "context deadline exceeded", "no such host", "net/http: nil Context",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent",
        "cannot create DailyCO result", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .rc = i % 2 ? 1 : -1, .error = errors[i]}}};
        results = run(detector, input, true, &steps, false); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "daily %s daily %s", key, other);
    script steps = {.count = 2, .rows = {{.key = key, .status = 200, .rc = 1, .error = "context canceled"}, {.key = other, .status = 204}}};
    results = run(detector, input, true, &steps, false); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other, true); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char key[65], input[96]; make_key(key, 0); snprintf(input, sizeof(input), "daily %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_shared_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\nagent" : NULL};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_alloc_after);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
    CHECK(results->items[0].secret_parts == prior->secret_parts);
}

static void resource_rollback(const br_detector *detector)
{
    char key[65], other[65], input[192]; make_key(key, 0); make_key(other, 7);
    snprintf(input, sizeof(input), "daily %s daily %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures captures = {0}; char *error = NULL;
    fail_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &captures, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&captures);
    for (int mode = 0; mode < 3; ++mode) {
        br_result owned = {0}; br_results results = {0};
        CHECK(br_finding_key(&owned, 777, "prior", "key") == 0); owned.verified = true;
        owned.verification_error = strdup("caller-owned"); CHECK(owned.verification_error && br_results_push(&results, &owned) == 0);
        br_result prior = results.items[0];
        script steps = {.count = 1, .rows = {{.key = key, .status = 200}}};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = scripted_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) fail_part_after = 2;
            else {
                fail_size = failure == 1 ? 64 : failure == 2 ? 65 : 2 * sizeof(br_span);
                /* Capture pointer/length arrays are the first two 64-byte
                 * allocations; the first Raw is third, before any skip/auth. */
                fail_alloc_after = failure == 1 ? 3 : failure == 2 ? 2 : 1;
            }
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error);
            const char *expected = failure < 2 ? "cannot create DailyCO result" : failure == 2 ? "out of memory copying detector capture" : "out of memory iterating regex";
            CHECK(!strcmp(error, expected) && !fail_part_after && !fail_alloc_after);
            CHECK(http.calls == (mode == 1 && failure == 0 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
            check_prior(&results, &prior); free(error); error = NULL; http.calls = http.releases = 0;
        }
        /* A genuine positive append-guard failure is fatal, never a keep. */
        size_t cap = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DailyCO result"));
        results.cap = cap; check_prior(&results, &prior); free(error); error = NULL;
        fail_part_after = 2;
        CHECK(detector->scan(detector, NULL, false, data, &results, NULL) == -1 && !fail_part_after); check_prior(&results, &prior);
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, &prior);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); combined_send_domain(detector); resource_rollback(detector);
    return test_finish("DailyCO direct native factory (upstream default disabled)");
}
