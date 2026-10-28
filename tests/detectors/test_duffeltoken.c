/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Inspect the provider request, then forward UNCHANGED to the actual shared
 * implementation. No response simulation, dedup removal, or guard bypass. */
#define br_http_send duffeltoken_real_http_send
#include "../../src/http.c"
#undef br_http_send

static char test_token[56], live_token[56];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_setter_after;
static const char *fail_setter_cause;
static bool inside_real_send, clobber_cause;
static const char *echo_guard_cause;
static const char *const *expected_tokens;
static const br_scan_ctx *expected_context;
static size_t expected_count, inspected;
static const char *borrowed_auth, *borrowed_token;
static br_slice borrowed_dedup;
static char *borrowed_cause;

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    /* Only replace the real guard's diagnostic allocation in the token-echo
     * regression. The unchanged guard STILL rejects before all send callbacks. */
    if (inside_real_send && echo_guard_cause && !strcmp(text, "unsupported HTTP request coalescing")) text = echo_guard_cause;
    if (!inside_real_send && fail_setter_after && fail_setter_cause && !strcmp(text, fail_setter_cause) && --fail_setter_after == 0) return NULL;
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                  br_http_response *response, char **error)
{
    CHECK(ctx && ctx == expected_context && inspected < expected_count);
    const char *token = expected_tokens[inspected++]; CHECK(strlen(token) == 55);
    CHECK(request && !strcmp(request->method, "GET") && !strcmp(request->url, "https://api.duffel.com/identity/customer/users?limit=1"));
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 1059); /* SANE selects 5s, but the guard runs BEFORE policy setup. */
    CHECK(!request->body.data && !request->body.len && request->nheaders == 3); /* Logical NoBody only; common UA is not reached behind the guard. */
    CHECK(!strcmp(request->headers[0].name, "Authorization") && strlen(request->headers[0].value) == 62);
    CHECK(!memcmp(request->headers[0].value, "Bearer ", 7) && !memcmp(request->headers[0].value + 7, token, 56));
    CHECK(!strcmp(request->headers[1].name, "Duffel-Version") && !strcmp(request->headers[1].value, "v2"));
    CHECK(!strcmp(request->headers[2].name, "Accept") && !strcmp(request->headers[2].value, "application/json"));
    CHECK(request->dedup_key.len == 60 && !memcmp(request->dedup_key.data, "1059:", 5) && !memcmp(request->dedup_key.data + 5, token, 55));
    CHECK(!borrowed_auth && !borrowed_dedup.data && !borrowed_cause);
    inside_real_send = true;
    int rc = duffeltoken_real_http_send(ctx, request, response, error);
    inside_real_send = false;
    CHECK(rc != 0 && error && *error); /* Forwarded real guard, never manufacture mock 200/403. */
    if (ctx->transport && ctx->transport->release) {
        borrowed_auth = request->headers[0].value; borrowed_dedup = request->dedup_key;
        borrowed_token = token; borrowed_cause = *error;
    }
    return rc;
}

static void expect_requests(const br_scan_ctx *ctx, const char *const *tokens, size_t count)
{
    CHECK(!borrowed_auth && !borrowed_dedup.data && !borrowed_cause);
    expected_context = ctx; expected_tokens = tokens; expected_count = count; inspected = 0;
}

static void unexpected_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request;
    CHECK(!"DuffelToken coalescing must fail BEFORE any injected send callback");
}

static void release_guarded(void *user, br_http_response *response)
{
    CHECK(response && !response->status && !response->headers && !response->nheaders);
    CHECK(!response->body.data && !response->body.len && !response->body_error);
    CHECK(borrowed_auth && strlen(borrowed_auth) == 62 && !memcmp(borrowed_auth, "Bearer ", 7));
    CHECK(!memcmp(borrowed_auth + 7, borrowed_token, 56)); /* Includes NUL, live THROUGH release. */
    CHECK(borrowed_dedup.len == 60 && !memcmp(borrowed_dedup.data, "1059:", 5) && !memcmp(borrowed_dedup.data + 5, borrowed_token, 55));
    CHECK(borrowed_cause);
    if (clobber_cause) borrowed_cause[0] = 'X'; /* Result setter must ALREADY own its copied/redacted error. */
    borrowed_auth = borrowed_token = NULL; borrowed_dedup = (br_slice){0}; borrowed_cause = NULL;
    test_http_release(user, response);
}

static br_transport guarded_transport(test_http *http)
{
    return (br_transport){http, test_http_send, release_guarded};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(test_token) == 55 && strlen(live_token) == 55);
    CHECK(br_duffeltoken_init(NULL, &error) == -1 && error && !strcmp(error, "invalid DuffelToken detector output"));
    free(error); error = NULL;
    CHECK(br_duffeltoken_init(NULL, NULL) == -1);
    CHECK(br_duffeltoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_duffeltoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1059 && detector->version == 0 && !strcmp(detector->name, "DuffelToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Duffel is a flight search and booking API service. Duffel API tokens can be used to access and interact with flight search and booking APIs in test environments."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "duffel_test_") && !strcmp(detector->keywords[1], "duffel_live_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    /* Parent owns the exact DuffelTokenDetectorEnabled gate/default selection. */
    return detector;
}

static void check_result(const br_result *result, const char *token, const char *cause)
{
    CHECK(result->detector_type == 1059 && !result->detector_name);
    CHECK(result->raw.len == 55 && !memcmp(result->raw.data, token, 55));
    CHECK(result->redacted && strlen(result->redacted) == 18 && !memcmp(result->redacted, token, 15) && !strcmp(result->redacted + 15, "..."));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 55 && !memcmp(json_object_get_string(part), token, 55));
    CHECK(!result->verified && !result->verification_from_cache);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *token)
{
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = inspected; br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (token ? 1u : 0u) && inspected == before && !http.calls && !http.releases);
    if (token) check_result(&results.items[0], token, NULL);
    br_results_clear(&results);
}

typedef struct { size_t whole_end, calls; const char *token; } span_check;
static int consumed_delimiter(void *user, const br_span *groups, size_t count)
{
    span_check *check = user; ++check->calls;
    CHECK(count == 3 && !groups[0].begin && groups[0].end == check->whole_end);
    CHECK(!groups[1].begin && groups[1].end == 55 && groups[2].begin == 7 && groups[2].end == 11);
    CHECK(!memcmp(check->token + groups[2].begin, "test", 4));
    return 0;
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[56];
    const struct { const char *format; bool matches; } cases[] = {
        {"%s", true}, {"'%s'", true}, {"-%s", true}, {"x%s", false}, {"_%s", false},
        {"%sA", false}, {"%s9", false}, {"%s_", false}, {"%s-", false}, {"%s!more", true},
        {"%s\r\n", true}, {"%s\n", true}, {"\xc3\xa9%s\xc3\xa9", true}, {"%.54s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, test_token);
        extraction_case(detector, input, strlen(input), cases[i].matches ? test_token : NULL);
    }
    extraction_case(detector, live_token, 55, live_token);
    memcpy(changed, test_token, sizeof(changed)); changed[0] = 'D'; extraction_case(detector, changed, 55, NULL);
    memcpy(changed, test_token, sizeof(changed)); changed[7] = 'T'; extraction_case(detector, changed, 55, NULL);
    memcpy(changed, test_token, sizeof(changed)); changed[30] = '+'; extraction_case(detector, changed, 55, NULL);
    memcpy(changed, test_token, 12); memset(changed + 12, 'a', 43); changed[55] = '\0';
    extraction_case(detector, changed, 55, changed); /* No local entropy/filter/validation. */
    const struct { const char *data; size_t len; } delimiters[] = {{"", 0}, {"!", 1}, {"\n", 1}, {"\0", 1}, {"\xf0\x9f\x98\x80", 4}};
    for (size_t i = 0; i < sizeof(delimiters) / sizeof(delimiters[0]); ++i) {
        memcpy(input, test_token, 55); memcpy(input + 55, delimiters[i].data, delimiters[i].len);
        span_check check = {.whole_end = 55 + delimiters[i].len, .token = test_token}; char *error = NULL;
        CHECK(br_regex_each(detector->state, (br_slice){(const unsigned char *)input, check.whole_end}, consumed_delimiter, &check, &error) == 0 && !error && check.calls == 1);
        extraction_case(detector, input, check.whole_end, test_token);
    } /* Group 0 CONSUMES exactly one delimiter rune, including LF/NUL, not a lookahead. */
    extraction_case(detector, NULL, 0, NULL);
}

static void unique_and_guarded(const br_detector *detector)
{
    char input[256], variant[56]; memcpy(variant, test_token, sizeof(variant)); variant[12] = 'q';
    snprintf(input, sizeof(input), "%s!%s\n%s %s", test_token, live_token, test_token, variant);
    const char *tokens[] = {test_token, live_token, variant};
    test_http http = {.response = {.status = 403, .body_error = "UNUSED"}, .inspect = unexpected_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "duffel-offline"};
    expect_requests(&ctx, tokens, 3);
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !inspected && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i], NULL);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        expect_requests(&ctx, tokens, 3); http.releases = 0; clobber_cause = true;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && inspected == 3 && !http.calls && http.releases == 3);
        CHECK(!borrowed_auth && !borrowed_dedup.data && !borrowed_cause && http.response.status == 403 && !strcmp(http.response.body_error, "UNUSED"));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i], "unsupported HTTP request coalescing");
        br_results_clear(&results);
    } /* Original-case uniqueness, not normalization or a persistent verification cache. */
    clobber_cause = false; size_t before = inspected;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 3 && inspected == before);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i], "net/http: nil Context");
    br_results_clear(&results);
    /* Prepared 403/body values NEVER reach the verifier. 200/403 success,
     * 401 rejection, other statuses, full singleflight and common-UA execution
     * remain UNEXERCISED/unsupported, not fake-success verification evidence. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void retained_errors(const br_detector *detector)
{
    const char *tokens[] = {test_token}; size_t cancellations = 0;
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        expect_requests(&contexts[i], tokens, 1); http.releases = 0;
        br_results results = test_scan(detector, &contexts[i], true, test_token, 55);
        CHECK(results.len == 1 && inspected == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        check_result(&results.items[0], test_token, i ? "unsupported HTTP request coalescing" : "HTTP transport not installed");
        br_results_clear(&results);
    }
    CHECK(!cancellations); /* Guard precedes cancellation/header/UA processing; not cancellation parity. */
    char input[128], echo[192], first[192], second[192];
    snprintf(input, sizeof(input), "%s\n%s", test_token, live_token);
    snprintf(echo, sizeof(echo), "request %s / %s", test_token, live_token);
    snprintf(first, sizeof(first), "request [REDACTED] / %s", live_token);
    snprintf(second, sizeof(second), "request %s / [REDACTED]", test_token);
    const char *pair[] = {test_token, live_token}; br_scan_ctx ctx = {.transport = &transport};
    expect_requests(&ctx, pair, 2); http.releases = 0; echo_guard_cause = echo; clobber_cause = true;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && inspected == 2 && !http.calls && http.releases == 2);
    check_result(&results.items[0], test_token, first); check_result(&results.items[1], live_token, second);
    br_results_clear(&results); echo_guard_cause = NULL; clobber_cause = false;
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.redacted = strdup("prior"); prior.verification_error = strdup("caller-owned"); CHECK(prior.redacted && prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
    CHECK(results->items[0].redacted == prior.redacted && !strcmp(prior.redacted, "prior"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "%s\n%s", test_token, live_token);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *tokens[] = {test_token, live_token};
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create DuffelToken result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 19; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot redact DuffelToken result") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL; /* Redaction failure wins over later nil-context retention. */
    expect_requests(&ctx, tokens, 1); fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create DuffelToken result") && !fail_part_after && inspected == 1 && !http.calls && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    expect_requests(&ctx, tokens, 1); http.releases = 0; fail_alloc_size = 19; fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot redact DuffelToken result") && !fail_alloc_after && inspected == 1 && !http.calls && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    expect_requests(&ctx, tokens, 2); http.releases = 0;
    fail_setter_cause = "unsupported HTTP request coalescing"; fail_setter_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set DuffelToken verification error") && !fail_setter_after && inspected == 2 && !http.calls && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    fail_setter_cause = "net/http: nil Context"; fail_setter_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot set DuffelToken verification error") && !fail_setter_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 3 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 56; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    expect_requests(&ctx, tokens, 1); http.releases = 0;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DuffelToken result")); results.cap = capacity;
    CHECK(inspected == 1 && !http.calls && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    expect_requests(&ctx, tokens, 2); http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && inspected == 2 && !http.calls && http.releases == 2);
    check_result(&results.items[0], test_token, "unsupported HTTP request coalescing"); check_result(&results.items[1], live_token, "unsupported HTTP request coalescing");
    br_results_clear(&results);
}

int main(void)
{
    memcpy(test_token, "duffel_test_", 12); test_secret(test_token + 12, 43, 0);
    memcpy(live_token, "duffel_live_", 12); test_secret(live_token + 12, 43, 7);
    test_token[12] = 'Q'; test_token[20] = '_'; test_token[33] = '-'; test_token[54] = '-';
    live_token[12] = 'R'; live_token[20] = '_'; live_token[33] = '-';
    const br_detector *detector = descriptor();
    extraction(detector); unique_and_guarded(detector); retained_errors(detector); fatal_resources(detector);
    return test_finish("DuffelToken extraction/request/rollback + real coalescing guard (verification unsupported)");
}
