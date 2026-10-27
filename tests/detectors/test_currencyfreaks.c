/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_currencyfreaks_init(const br_detector **out, char **error);

static size_t fail_size, fail_alloc_after, fail_part_after;

/* Exercise real shared resource boundaries, without inventing URL copies. */
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

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_currencyfreaks_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Currencyfreaks detector output"));
    free(error); error = NULL;
    fail_size = sizeof("(?i:currencyfreaks)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_currencyfreaks_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_currencyfreaks_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_currencyfreaks_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 499 && detector->version == 0 && !strcmp(detector->name, "Currencyfreaks"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Currencyfreaks provides exchange rates and currency conversion API services. The API keys can be used to access and retrieve exchange rate data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "currencyfreaks"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_currencyfreaks_init(NULL, NULL) == -1);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 499, key, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_get_string_len(part) == 32);
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
    char key[33], changed[33], input[512]; test_secret(key, 32, 0);
    const struct { const char *format; bool match; } cases[] = {
        {"currencyfreaks '%s'", true}, {"preCuRrEnCyFrEaKsSuffix\r\n%s", true},
        {"CURRENCYFREAKS %s", true}, {"currencyfreaks .%s!", true}, {"%s", false},
        {"%s currencyfreaks", false}, {"currency freaks %s", false},
        {"currencyfreaks%s", false}, {"currencyfreaks _%s", false}, {"currencyfreaks %s_", false},
        {"currencyfreaks %s0", false}, {"currencyfreaks %.31s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_one(detector, input, strlen(input), cases[i].match ? key : NULL);
    }
    const char invalid[] = {'A', '_', '-', '/', '=', ' ', '\t', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed)); changed[17] = invalid[i];
        snprintf(input, sizeof(input), "CURRENCYFREAKS %s", changed); expect_one(detector, input, strlen(input), NULL);
    }
    memset(changed, 'g', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "currencyfreaks %s", changed);
    expect_one(detector, input, strlen(input), changed); /* Lower alnum, not hex; no entropy/FP filtering. */
    const size_t prefix_len = strlen("currencyfreaks");
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "currencyfreaks", prefix_len); memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_one(detector, input, strlen(input), gap == 40 ? key : NULL);
        size_t at = prefix_len;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
        memcpy(input + at, key, sizeof(key)); expect_one(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "currencyfreaks %s %s", key, key);
    expect_one(detector, input, strlen(input), key); /* Whole matches consume the keyword, too. */
    static const unsigned char prefix[] = "bad\xff\0currencyfreaks\0";
    memcpy(input, prefix, sizeof(prefix) - 1); memcpy(input + sizeof(prefix) - 1, key, 32);
    expect_one(detector, input, sizeof(prefix) - 1 + 32, key); /* No global UTF-8 guard or C-string truncation. */
    snprintf(input, sizeof(input), "currencyfreaks \xc3\xa9%s\xc3\xa9", key);
    expect_one(detector, input, strlen(input), key); /* ASCII word boundaries. */
    expect_one(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *error; int status, rc; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; } script;

static void check_url(const char *url, const char *key)
{
    static const char prefix[] = "https://api.currencyfreaks.com/latest?apikey=";
    static const char suffix[] = "&format=xml";
    CHECK(url && strlen(url) == sizeof(prefix) - 1 + 32 + sizeof(suffix) - 1);
    CHECK(!memcmp(url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(url + sizeof(prefix) - 1, key, 32));
    CHECK(!memcmp(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix))); /* Including NUL. */
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->ctx);
    CHECK(request->detector_type == 499 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, steps->rows[at].key);
    steps->borrowed_url = request->url;
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* No Content-Type, API-key header, Accept, Authorization or invented Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent") &&
        !strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog offline-currencyfreaks" : "TruffleHog"));
    static const unsigned char invalid_xml[] = {'<', '?', '\0', 0xff};
    http->response = (br_http_response){.status = steps->rows[at].status,
        .body = {invalid_xml, sizeof(invalid_xml)}, .body_error = "ignored XML body read error"};
    http->send_rc = steps->rows[at].rc; http->send_error = steps->rows[at].error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->borrowed_url) {
        CHECK(http->calls && http->calls <= steps->count);
        check_url(steps->borrowed_url, steps->rows[http->calls - 1].key); /* Complete stack URL is still live. */
        steps->borrowed_url = NULL;
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
    br_scan_ctx ctx = {.transport = &transport, .user_agent = suffix ? "offline-currencyfreaks" : NULL}; steps->ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void verification(const br_detector *detector)
{
    char key[33], other[33], input[256]; test_secret(key, 32, 0); test_secret(other, 32, 7);
    snprintf(input, sizeof(input), "currencyfreaks %s\ncurrencyfreaks %s\ncurrencyfreaks %s", key, other, key);
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
    snprintf(input, sizeof(input), "currencyfreaks %s", key);
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = statuses[i]}}};
        results = run(detector, input, true, &steps, false); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"context canceled", "context deadline exceeded", "no such host", "net/http: nil Context",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent",
        "cannot create Currencyfreaks result", "cannot format Currencyfreaks URL", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .rc = i % 2 ? 1 : -1, .error = errors[i]}}};
        results = run(detector, input, true, &steps, false); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "currencyfreaks %s currencyfreaks %s", key, other);
    script steps = {.count = 2, .rows = {{.key = key, .status = 200, .rc = 1, .error = "context canceled"}, {.key = other, .status = 204}}};
    results = run(detector, input, true, &steps, false); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other, true); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_headers(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char key[33], input[80]; test_secret(key, 32, 0); snprintf(input, sizeof(input), "currencyfreaks %s", key);
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
    char key[33], other[33], input[128]; test_secret(key, 32, 0); test_secret(other, 32, 7);
    snprintf(input, sizeof(input), "currencyfreaks %s currencyfreaks %s", key, other);
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
                fail_size = failure == 2 ? 33 : 2 * sizeof(br_span);
                /* The regex group workspace and each Raw are all 32 bytes. */
                fail_alloc_after = failure == 1 ? 3 : failure == 2 ? 2 : 1;
            }
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error);
            const char *expected = failure < 2 ? "cannot create Currencyfreaks result" : failure == 2 ? "out of memory copying detector capture" : "out of memory iterating regex";
            CHECK(!strcmp(error, expected) && !fail_part_after && !fail_alloc_after);
            CHECK(http.calls == (mode == 1 && failure < 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
            check_prior(&results, &prior); free(error); error = NULL; http.calls = http.releases = 0;
        }
        /* A genuine positive append-guard failure is fatal, never a keep/skip. */
        size_t cap = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Currencyfreaks result"));
        results.cap = cap; check_prior(&results, &prior); free(error); error = NULL;
        fail_size = 32; fail_alloc_after = 3;
        CHECK(detector->scan(detector, NULL, false, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, &prior);
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, &prior);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); combined_send_domain(detector); resource_rollback(detector);
    return test_finish("Currencyfreaks");
}
