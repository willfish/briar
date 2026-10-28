/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Observe construction, then forward UNCHANGED to the real shared adapter.
 * Never remove the key, replace a response, or bypass coalescing for success. */
#define br_http_send finage_real_http_send
#include "../../src/http.c"
#undef br_http_send

static char key1[40], key2[40];
static const char base_url[] = "https://api.finage.co.uk/symbol-list/crypto?apikey=";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, inspected, send_callbacks;
static bool fail_guard_copy;
static const char *const *expected_keys;
static size_t expected_count;
static const br_scan_ctx *expected_context;
static const char *borrowed_url, *borrowed_key;
static br_slice borrowed_dedup;

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_guard_copy && !strcmp(text, "unsupported HTTP request coalescing")) { fail_guard_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    if (ctx && br_http_client_is_owned(ctx->transport))
        return finage_real_http_send(ctx, request, response, error);
    CHECK(ctx && ctx == expected_context && inspected < expected_count);
    const char *key = expected_keys[inspected++]; CHECK(strlen(key) == 39);
    CHECK(request && !strcmp(request->method, "GET") && strlen(request->url) == 90 && !memcmp(request->url, base_url, 51));
    CHECK(!memcmp(request->url + 51, key, 40)); /* Complete URL includes NUL. */
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 423);
    CHECK(!request->body.data && !request->body.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(request->dedup_key.len == 43 && !memcmp(request->dedup_key.data, "423:", 4) && !memcmp(request->dedup_key.data + 4, key, 40)); /* Full 43-byte key PLUS storage NUL. */
    CHECK(!borrowed_url && !borrowed_dedup.data);
    int rc = finage_real_http_send(ctx, request, response, error);
    CHECK(rc != 0 && error); /* Real guard, no fake 200/2xx path. Diagnostic allocation may legitimately fail. */
    if (*error) CHECK(!strcmp(*error, ctx->transport ? "unsupported HTTP request coalescing" : "HTTP transport not installed"));
    CHECK(!response->status && !response->headers && !response->nheaders && !response->body.data && !response->body.len && !response->body_error);
    if (ctx->transport && ctx->transport->release) {
        borrowed_url = request->url; borrowed_key = key; borrowed_dedup = request->dedup_key;
    }
    return rc;
}

static void expect_requests(const br_scan_ctx *ctx, const char *const *keys, size_t count)
{
    CHECK(!borrowed_url && !borrowed_dedup.data); expected_context = ctx; expected_keys = keys; expected_count = count; inspected = 0;
}

static void unexpected_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request; ++send_callbacks;
    CHECK(!"Finage's nonempty dedup key must be rejected BEFORE every send callback");
}

static void release_guarded(void *user, br_http_response *response)
{
    CHECK(response && !response->status && !response->headers && !response->nheaders);
    CHECK(!response->body.data && !response->body.len && !response->body_error);
    CHECK(borrowed_url && strlen(borrowed_url) == 90 && !memcmp(borrowed_url, base_url, 51));
    CHECK(!memcmp(borrowed_url + 51, borrowed_key, 40));
    CHECK(borrowed_dedup.len == 43 && !memcmp(borrowed_dedup.data, "423:", 4) && !memcmp(borrowed_dedup.data + 4, borrowed_key, 40));
    borrowed_url = borrowed_key = NULL; borrowed_dedup = (br_slice){0}; /* All URL/key bytes, including storage NULs, live THROUGH release. */
    test_http_release(user, response);
}

static br_transport guarded_transport(test_http *http) { return (br_transport){http, test_http_send, release_guarded}; }

static void make_key(char out[40], size_t shift)
{
    static const char alphabet[] = "B7C9D2E5F6G8H3J4K1M0N2P4Q6R8S1T3U5V7W9X2Y4Z6";
    memcpy(out, "API_KEY", 7);
    for (size_t i = 0; i < 32; ++i) out[7 + i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    out[39] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 39 && strlen(key2) == 39 && strlen(base_url) == 51);
    CHECK(br_finage_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Finage detector output"));
    free(error); error = NULL;
    CHECK(br_finage_init(NULL, NULL) == -1);
    CHECK(br_finage_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_finage_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 423 && detector->version == 0 && !strcmp(detector->name, "Finage"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Finage provides financial data APIs for stocks, forex, and cryptocurrencies. Finage API keys can be used to access and retrieve financial data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "finage")); /* Dispatch only, never an extraction prefix. */
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key)
{
    test_key_result(result, 423, key, "key");
    CHECK(result->raw.len == 39 && !result->verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 39);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *key)
{
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport}; size_t before = inspected;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (key ? 1u : 0u) && inspected == before && !http.calls && !http.releases);
    if (key) check_result(&results.items[0], key);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[40];
    const struct { const char *format; bool matches; } cases[] = {
        {"%s", true}, {"'%s'", true}, {"FINAGE %s", true}, {"not-a-provider: %s", true},
        {"x%s", false}, {"_%s", false}, {"%sA", false}, {"%s9", false}, {"%s_", false},
        {"%s-", true}, {"\xc3\xa9%s\xc3\xa9", true}, {"%.38s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1); extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const size_t positions[] = {0, 4, 15}; const char invalid_case[] = {'a', 'k', 'g'};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[positions[i]] = invalid_case[i]; extraction_case(detector, changed, 39, NULL);
    }
    const char invalid[] = "_-+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[20] = invalid[i]; extraction_case(detector, changed, 39, NULL);
    }
    memcpy(changed, "API_KEY", 7); memset(changed + 7, 'Z', 32); changed[39] = '\0'; extraction_case(detector, changed, 39, changed); /* Not hex, no entropy/token validator. */
    memset(input, '!', 100); memcpy(input + 100, key1, 39); extraction_case(detector, input, 139, key1); /* No PrefixRegex distance window. */
    int n = snprintf(input, sizeof(input), "\xff\n%s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    input[0] = '\0'; memcpy(input + 1, key1, 39); extraction_case(detector, input, 40, key1);
    extraction_case(detector, NULL, 0, NULL);
}

static void occurrences_and_actual_guard(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "%s\n%s\n%s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200, .body_error = "UNUSED"}, .inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "finage-offline"}; expect_requests(&ctx, keys, 3);
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !inspected && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
    CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts); br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        expect_requests(&ctx, keys, 3); http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && inspected == 3 && !http.calls && http.releases == 3 && !borrowed_url && !borrowed_dedup.data);
        CHECK(http.response.status == 200 && !strcmp(http.response.body_error, "UNUSED"));
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
        br_results_clear(&results);
    } /* Original duplicates/repeat scans are not uniqueness or persistent cache. */
    http.releases = 0; size_t before = inspected;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && inspected == before && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3 && inspected == before);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
    br_results_clear(&results);
    /* Prepared 200/read-error values NEVER reach the verifier. Common UA/5s
     * policy setup is also behind the guard. No all-2xx/body-ignore, singleflight
     * buffering/replay/cancellation or native-success parity is proven here. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_shared_failures(const br_detector *detector)
{
    const char *keys[] = {key1}; size_t cancellations = 0;
    test_http http = {.response = {.status = 299}, .inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        expect_requests(&contexts[i], keys, 1); http.releases = 0; if (i == 5) fail_guard_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, key1, 39);
        CHECK(results.len == 1 && inspected == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_guard_copy);
        check_result(&results.items[0], key1); br_results_clear(&results);
    }
    CHECK(!cancellations && http.response.status == 299); /* Coalescing guard precedes cancellation/header setup; not cancellation/status-success evidence. */
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "%s\n%s", key1, key2); br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Finage result") && !fail_part_after); check_prior(&results, prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect_requests(&ctx, keys, 2); fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Finage result") && !fail_part_after && inspected == 1 && !http.calls && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL; /* Late own failure rolls back earlier suppressed-false finding, not caller data. */
    expect_requests(&ctx, keys, 2); http.releases = 0; fail_alloc_size = 39; fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Finage result") && !fail_alloc_after && inspected == 1 && !http.calls && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 40; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL;
    expect_requests(&ctx, keys, 2); http.releases = 0; size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && !inspected); check_prior(&results, prior); /* Constructor skips never append. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Finage result")); results.cap = capacity;
    CHECK(inspected == 1 && !http.calls && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    expect_requests(&ctx, keys, 2); http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && inspected == 2 && !http.calls && http.releases == 2); check_result(&results.items[0], key1); check_result(&results.items[1], key2); br_results_clear(&results);
}

static void inspect_owned(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(!ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > 0);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->detector_type == 423);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 5000);
    CHECK(strlen(request->url) == 90 && !memcmp(request->url, base_url, 51) && !memcmp(request->url + 51, key1, 40));
    CHECK(request->dedup_key.len == 43 && !memcmp(request->dedup_key.data, "423:", 4) && !memcmp(request->dedup_key.data + 4, key1, 39));
    CHECK(!request->body.data && !request->body.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog owned-finage"));
}

static void owned_verification(const br_detector *detector)
{
    const struct { int status, send_rc; bool read_error, verified; } cases[] = {
        {204, 0, false, true}, {299, 0, false, true},
        {401, 0, false, false}, {503, 0, false, false},
        {200, 1, false, false}, {200, 0, true, false},
    };
    static const unsigned char body[] = "ignored\0body";
    test_http *http = calloc(1, sizeof(*http)); CHECK(http); http->inspect = inspect_owned;
    br_http_owned_backend backend = {.transport = test_transport(http), .destroy = free};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "owned-finage"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http->response = (br_http_response){.status = cases[i].status,
            .body = {body, sizeof(body) - 1}, .body_error = cases[i].read_error ? "" : NULL};
        http->send_rc = cases[i].send_rc;
        http->send_error = cases[i].send_rc ? "synthetic owned send failure" : NULL;
        br_results results = test_scan(detector, &ctx, true, key1, 39);
        CHECK(results.len == 1 && http->calls == i + 1 && http->releases == i + 1);
        test_key_result(&results.items[0], 423, key1, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client);
}

int main(void)
{
    make_key(key1, 0); make_key(key2, 7); const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_actual_guard(detector); suppressed_shared_failures(detector); resources_and_rollback(detector);
    CHECK(!send_callbacks); /* The ordinary transport's guard still blocks callbacks. */
    owned_verification(detector);
    return test_finish("Finage ordinary guard + owned singleflight request/status verification");
}
