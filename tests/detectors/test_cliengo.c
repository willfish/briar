/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

static const char key1[] = "01234567-89ab-0def-0123-456789abcdef";
static const char key2[] = "fedcba98-7654-f210-ffff-fedcba987654";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, 36); copy[36] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_cliengo_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 710 && detector->version == 0 && !strcmp(detector->name, "Cliengo"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Cliengo is a chatbot service that helps businesses convert website visitors into leads. "
        "Cliengo API keys can be used to access and manage the chatbot configurations and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cliengo"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_cliengo_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_cliengo_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_cliengo_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Cliengo detector output"));
    free(error); CHECK(br_cliengo_init(NULL, NULL) != 0);
    return detector;
}

static void unexpected_provider_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request;
    CHECK(!"keyed Cliengo verification must be blocked BEFORE the injected send callback");
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
    test_key_result(result, 710, key, "key");
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
    char input[192], changed[37];
    const struct { const char *format; size_t count; } cases[] = {
        {"cliengo '%s'", 1}, {"CLIENGO=%s", 1}, {"cLiEnGo\t%s", 1},
        {"precliengosuffix %s", 1}, {"cliengo\r\n%s\t", 1},
        {"%s", 0}, {"%s cliengo", 0}, {"cli engo %s", 0}, {"cliengo %.35s", 0},
        {"cliengo A%s", 0}, {"cliengo %sA", 0}, {"cliengo _%s", 0}, {"cliengo %s_", 0},
        {"cliengo +%s/", 1}, {"cliengo %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        expect_extraction(detector, input, strlen(input), key1, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "cliengo", 7); memset(input + 7, ':', gap); memcpy(input + 7 + gap, key1, sizeof(key1));
        expect_extraction(detector, input, strlen(input), key1, gap == 40 ? 1 : 0);
    }
    memcpy(changed, key1, sizeof(changed)); changed[10] = 'A';
    snprintf(input, sizeof(input), "CLIENGO %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0); /* Only keyword is CI. */
    changed[10] = 'g'; snprintf(input, sizeof(input), "cliengo %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key1, sizeof(changed)); changed[8] = '_';
    snprintf(input, sizeof(input), "cliengo %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    const char zero[] = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "cliengo %s", zero); expect_extraction(detector, input, strlen(input), zero, 1); /* No version/variant/entropy checks. */
    memcpy(input, "cliengo", 7); input[7] = '\0'; memcpy(input + 8, key1, 36);
    expect_extraction(detector, input, 44, key1, 1);
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
    static const unsigned char keyed[] = "710:01234567-89ab-0def-0123-456789abcdef";
    CHECK(sizeof(keyed) - 1 == 40);
    request.dedup_key = (br_slice){keyed, sizeof(keyed) - 1}; http.calls = http.releases = 0;
    http.inspect = unexpected_provider_send; transport.release = release_guarded;
    CHECK(br_http_send(&ctx, &request, &response, &error) != 0 && error && !strcmp(error, "unsupported HTTP request coalescing"));
    CHECK(!http.calls && !response.status && !response.body_error); free(error);
    br_http_release(&ctx, &response); CHECK(!http.calls && http.releases == 1);
    /* Direct unkeyed HTTP control is NOT a Cliengo verification success. */
}

typedef struct {
    int status;
    bool send_error, verified;
    const char *body_error;
} owned_case;

typedef struct {
    const owned_case *script;
    size_t calls, releases;
    const br_http_request *held;
    bool *destroyed;
} owned_http;

static const char owned_url[] = "https://api.cliengo.com/1.0/account?api_key=01234567-89ab-0def-0123-456789abcdef";
static const unsigned char owned_key[] = "710:01234567-89ab-0def-0123-456789abcdef";
static const unsigned char owned_body[] = {'r', 0, 'p'};

static void inspect_owned_request(const br_http_request *request)
{
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, owned_url));
    CHECK(request->detector_type == 710 && request->dedup_key.len == 40);
    CHECK(!memcmp(request->dedup_key.data, owned_key, sizeof(owned_key) - 1));
    /* The five-second profile budget includes snapshot/worker scheduling. */
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms > 0 && request->timeout_ms <= 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog cliengo-offline"));
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    owned_http *http = user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(ctx->deadline_monotonic_ms > 0 && !ctx->cancelled && !ctx->cancel_user);
    CHECK(!http->held && http->calls == http->releases);
    inspect_owned_request(request);
    http->held = request; ++http->calls;
    *response = (br_http_response){.status = http->script->status,
        .body = {owned_body, sizeof(owned_body)}, .body_error = http->script->body_error};
    *error = http->script->send_error ? strdup("synthetic send failure") : NULL;
    CHECK(!http->script->send_error || *error);
    return http->script->send_error ? 1 : 0;
}

static void owned_release(void *user, br_http_response *response)
{
    owned_http *http = user;
    CHECK(http->held && http->calls == http->releases + 1);
    inspect_owned_request(http->held); /* Prepared request remains valid through raw release. */
    CHECK(response->status == http->script->status && response->body_error == http->script->body_error);
    CHECK(response->body.len == sizeof(owned_body) && !memcmp(response->body.data, owned_body, sizeof(owned_body)));
    *response = (br_http_response){0}; http->held = NULL; ++http->releases;
}

static void owned_destroy(void *user)
{
    owned_http *http = user;
    CHECK(!http->held && http->calls == http->releases && !*http->destroyed);
    *http->destroyed = true;
    free(http);
}

static void owned_client_verification(const br_detector *detector)
{
    const owned_case cases[] = {
        {200, false, true, NULL}, {204, false, true, NULL}, {299, false, true, NULL},
        {401, false, false, NULL}, {500, false, false, NULL},
        {200, true, false, NULL}, {200, false, false, "synthetic body-read failure"},
        {200, false, false, ""},
    };
    char input[96]; snprintf(input, sizeof(input), "cliengo %s", key1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        bool destroyed = false;
        owned_http *http = calloc(1, sizeof(*http)); CHECK(http);
        http->script = &cases[i]; http->destroyed = &destroyed;
        br_http_owned_backend backend = {{http, owned_send, owned_release}, owned_destroy};
        br_http_client *client = NULL; char *error = NULL;
        CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &error) == 0 && client && !error);
        br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "cliengo-offline"};
        CHECK(br_http_client_is_owned(ctx.transport));
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], 710, key1, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        if (cases[i].body_error) {
            /* Observe Do failure itself, not just the provider's false result.
             * This probe retains the full key and uses the same owned dispatch. */
            br_http_request request = {.method = "GET", .url = owned_url, .profile = BR_HTTP_SANE,
                .detector_type = 710, .dedup_key = {owned_key, sizeof(owned_key) - 1}};
            br_http_response response = {0};
            CHECK(br_http_send(&ctx, &request, &response, &error) != 0);
            CHECK(error && !strcmp(error, cases[i].body_error));
            CHECK(!response.status && !response.body.data && !response.body.len && !response.body_error);
            br_http_release(&ctx, &response); free(error); error = NULL;
        }
        CHECK(br_http_client_drain(client, &error) == 0 && !error);
        CHECK(http->calls == (cases[i].body_error ? 2u : 1u) && http->releases == http->calls && !http->held);
        br_http_client_destroy(client); CHECK(destroyed);
    }
}

static void occurrences_and_blocked_verification(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "cliengo %s\nCLIENGO %s\ncliengo %s", key1, key2, key1);
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
    CHECK(results.len == 3 && !http.calls && http.releases == 3); /* No scan-local/persistent consumption. */
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
    char input[96]; snprintf(input, sizeof(input), "cliengo %s", key1);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send}; br_transport transport = guarded_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); check_unverified(&results.items[0], key1); br_results_clear(&results);
    }
    /* Guard/missing-transport paths only: no claim of coalesced cancellation,
     * deadline, header cloning, ReadAll/error propagation or replay coverage. */
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 710, (br_slice){(const unsigned char *)key1, 36}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Core failures need not be negative. */
    char input[192]; snprintf(input, sizeof(input), "cliengo %s\ncliengo %s\ncliengo %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200}, .inspect = unexpected_provider_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Cliengo result"));
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
    CHECK(strlen(key1) == 36 && strlen(key2) == 36);
    const br_detector *detector = descriptor();
    extraction(detector); unchanged_guard_with_unkeyed_control(); occurrences_and_blocked_verification(detector);
    rejected_context_paths(detector); resource_rollback(detector); owned_client_verification(detector);
    return test_finish("Cliengo extraction + borrowed guard + owned keyed verification");
}
