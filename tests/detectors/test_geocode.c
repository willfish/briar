/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Inspect provider assembly, then forward UNCHANGED to the actual shared guard.
 * No key removal, guard bypass, or fabricated successful response. */
#define br_http_send geocode_real_http_send
#include "../../src/http.c"
#undef br_http_send

static char key1[29], key2[29];
static const char base_url[] = "https://geocode.xyz/51.4647,0.0079?json=1&auth=";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, inspected;
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

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                 br_http_response *response, char **error)
{
    /* Exercise the actual supported owned-client dispatcher without changing
     * any credential key or the ordinary borrowed-transport rejection. */
    if (ctx && br_http_client_is_owned(ctx->transport))
        return geocode_real_http_send(ctx, request, response, error);
    CHECK(ctx == expected_context && inspected < expected_count);
    const char *key = expected_keys[inspected++];
    CHECK(request && !strcmp(request->method, "GET"));
    CHECK(strlen(request->url) == sizeof(base_url) - 1 + 28);
    CHECK(!memcmp(request->url, base_url, sizeof(base_url) - 1));
    CHECK(!memcmp(request->url + sizeof(base_url) - 1, key, 29));
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 486);
    CHECK(!request->headers && !request->nheaders && !request->body.data && !request->body.len);
    CHECK(request->dedup_key.len == 32 && !memcmp(request->dedup_key.data, "486:", 4));
    CHECK(!memcmp(request->dedup_key.data + 4, key, 28));
    CHECK(!borrowed_url && !borrowed_dedup.data);
    int rc = geocode_real_http_send(ctx, request, response, error);
    CHECK(rc != 0 && error && *error);
    CHECK(!strcmp(*error, ctx->transport ? "unsupported HTTP request coalescing" : "HTTP transport not installed"));
    CHECK(!response->status && !response->headers && !response->nheaders && !response->body.data && !response->body.len && !response->body_error);
    if (ctx->transport && ctx->transport->release) {
        borrowed_url = request->url; borrowed_key = key; borrowed_dedup = request->dedup_key;
    }
    return rc;
}

static void expect_requests(const br_scan_ctx *ctx, const char *const *keys, size_t count)
{
    CHECK(!borrowed_url && !borrowed_dedup.data);
    expected_context = ctx; expected_keys = keys; expected_count = count; inspected = 0;
}

static void unexpected_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request;
    CHECK(!"Mandatory nonempty coalescing key must stop BEFORE every transport callback");
}

static void release_guarded(void *user, br_http_response *response)
{
    CHECK(response && !response->status && !response->headers && !response->nheaders);
    CHECK(!response->body.data && !response->body.len && !response->body_error);
    CHECK(borrowed_url && strlen(borrowed_url) == sizeof(base_url) - 1 + 28);
    CHECK(!memcmp(borrowed_url, base_url, sizeof(base_url) - 1));
    CHECK(!memcmp(borrowed_url + sizeof(base_url) - 1, borrowed_key, 29));
    CHECK(borrowed_dedup.len == 32 && !memcmp(borrowed_dedup.data, "486:", 4));
    CHECK(!memcmp(borrowed_dedup.data + 4, borrowed_key, 28));
    borrowed_url = borrowed_key = NULL; borrowed_dedup = (br_slice){0};
    test_http_release(user, response);
}

static br_transport guarded_transport(test_http *http)
{
    return (br_transport){http, test_http_send, release_guarded};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 28 && strlen(key2) == 28);
    CHECK(br_geocode_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Geocode detector output")); free(error); error = NULL;
    CHECK(br_geocode_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_geocode_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 486 && detector->version == 0 && !strcmp(detector->name, "Geocode"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Geocode API keys can be used to access geolocation services, converting addresses into geographic coordinates and vice versa."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "geocode"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector; /* Enabled defaults membership is parent-owned. */
}

static void check_result(const br_result *result, const char *key)
{
    test_key_result(result, 486, key, "key");
    CHECK(result->raw.len == 28 && !result->verified && !result->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 28);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *key)
{
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; size_t before = inspected;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (key ? 1u : 0u) && inspected == before && !http.calls && !http.releases);
    if (key) check_result(&results.items[0], key);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[29];
    const struct { const char *format; bool matches; } cases[] = {
        {"geocode '%s'", true}, {"GEOcode=%s", true}, {"pregeocodesuffix:%s", true},
        {"geocode\r\n%s", true}, {"geocode\r%s", true}, {"geocode\n%s", true},
        {"geocode +%s/", true}, {"%s", false}, {"%s geocode", false},
        {"geo code %s", false}, {"geocode%s", false}, {"geocode x%s", false},
        {"geocode _%s", false}, {"geocode %s_", false}, {"geocode %s9", false},
        {"geocode %.27s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char invalid[] = "AFZ_-+./";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "GEOCODE %s", changed);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "geocode", 7); memset(input + 7, '.', gap); memcpy(input + 7 + gap, key1, 28);
        extraction_case(detector, input, 7 + gap + 28, gap == 40 ? key1 : NULL);
    }
    memset(changed, 'z', 28); changed[28] = '\0';
    snprintf(input, sizeof(input), "geocode %s", changed);
    extraction_case(detector, input, strlen(input), changed); /* No entropy/FP filter or hex restriction. */
    snprintf(input, sizeof(input), "geocode %s %s", key1, key2);
    extraction_case(detector, input, strlen(input), key1); /* Non-overlapping whole matches. */
    int n = snprintf(input, sizeof(input), "geocode%c%s", 0, key1);
    extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

static void occurrences_and_guard(const br_detector *detector)
{
    char input[160]; int n = snprintf(input, sizeof(input), "geocode %s\nGEOCODE %s\ngeocode %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200, .body_error = "UNUSED"}, .inspect = unexpected_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "geocode-offline"};
    for (int pass = 0; pass < 3; ++pass) {
        expect_requests(&ctx, keys, 3); http.releases = 0;
        br_results results = test_scan(detector, &ctx, pass != 0, input, (size_t)n);
        CHECK(results.len == 3 && inspected == (pass ? 3u : 0u) && !http.calls && http.releases == (pass ? 3u : 0u));
        CHECK(http.response.status == 200 && !strcmp(http.response.body_error, "UNUSED"));
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        br_results_clear(&results);
    }
    http.releases = 0; size_t before = inspected;
    br_results results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && inspected == before && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3 && inspected == before);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
    br_results_clear(&results);
    br_scan_ctx missing = {0}; expect_requests(&missing, keys, 3);
    results = test_scan(detector, &missing, true, input, (size_t)n);
    CHECK(results.len == 3 && inspected == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
    br_results_clear(&results);
    /* The prepared response NEVER reaches provider policy. 5s/common-UA setup,
     * body-marker/2xx branches and coalescing/replay are not accepted here. */
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "geocode %s\ngeocode %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result sentinel = {.detector_type = 777, .verified = true};
    sentinel.raw.data = malloc(5); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "prior", 5); sentinel.raw.len = 5;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); br_result prior = results.items[0]; char *error = NULL;
    /* Own capture failure is fatal before nil-context constructor skips. */
    fail_alloc_size = 29; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !fail_alloc_after);
    CHECK(!strcmp(error, "out of memory copying detector capture")); check_prior(&results, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Geocode result")); check_prior(&results, &prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; expect_requests(&ctx, keys, 2); fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Geocode result") && inspected == 1 && !http.calls && http.releases == 1);
    check_prior(&results, &prior); free(error); error = NULL; /* Roll back earlier false-kept finding only. */
    expect_requests(&ctx, keys, 2); http.releases = 0; size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && !inspected); check_prior(&results, &prior);
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot append Geocode result") && inspected == 1 && !http.calls && http.releases == 1);
    results.cap = capacity; check_prior(&results, &prior); free(error); br_results_clear(&results);
}

static void inspect_owned(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http;
    CHECK(!ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > 0);
    CHECK(!strcmp(r->method, "GET") && r->profile == BR_HTTP_SANE && r->detector_type == 486);
    CHECK(r->timeout_ms > 0 && r->timeout_ms <= 5000);
    CHECK(strlen(r->url) == sizeof(base_url) - 1 + 28 && !memcmp(r->url, base_url, sizeof(base_url) - 1));
    CHECK(!memcmp(r->url + sizeof(base_url) - 1, key1, 29));
    CHECK(r->dedup_key.len == 32 && !memcmp(r->dedup_key.data, "486:", 4) && !memcmp(r->dedup_key.data + 4, key1, 28));
    CHECK(!r->body.data && !r->body.len && r->nheaders == 1);
    CHECK(!strcmp(r->headers[0].name, "User-Agent") && !strcmp(r->headers[0].value, "TruffleHog owned-geocode"));
}

static void owned_verification(const br_detector *detector)
{
    static const unsigned char marker[] = "junk\0\"remaining_credits\" : 4";
    static const unsigned char compact[] = "{\"remaining_credits\":4}";
    const struct { int status, send_rc; bool marker, read_error, verified; } cases[] = {
        {201, 0, true, false, true}, {299, 0, true, false, true},
        {200, 0, false, false, false}, {500, 0, true, false, false},
        {200, 0, true, true, false}, {200, 1, true, false, false},
    };
    test_http *http = calloc(1, sizeof(*http)); CHECK(http);
    http->inspect = inspect_owned;
    br_http_owned_backend backend = {.transport = test_transport(http), .destroy = free};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "owned-geocode"};
    char input[48]; snprintf(input, sizeof(input), "geocode %s", key1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http->response = (br_http_response){.status = cases[i].status,
            .body = {cases[i].marker ? marker : compact, cases[i].marker ? sizeof(marker) - 1 : sizeof(compact) - 1},
            .body_error = cases[i].read_error ? "" : NULL};
        http->send_rc = cases[i].send_rc; http->send_error = cases[i].send_rc ? "synthetic owned send error" : NULL;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http->calls == i + 1 && http->releases == i + 1);
        test_key_result(&results.items[0], 486, key1, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client);
}

int main(void)
{
    test_secret(key1, 28, 0); test_secret(key2, 28, 7);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_guard(detector); resources_and_rollback(detector); owned_verification(detector);
    return test_finish("Geocode ordinary guard + owned singleflight request/body/status verification");
}
