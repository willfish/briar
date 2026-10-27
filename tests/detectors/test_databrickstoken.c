/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char token1[] = "dapi0123456789abcdef0123456789abcdef";
static const char token2[] = "dapifedcba9876543210fedcba9876543210-7";
static const char domain1[] = "synthetic.cloud.databricks.com";
static const char domain2[] = "workspace-9.gcp.databricks.com";
static const char domain3[] = "adb-000.azuredatabricks.net";
static const char path[] = "/api/2.0/preview/scim/v2/Me";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_cause_after;
static size_t url_size, url_allocations;
static const char *fail_cause_text;
static bool fail_agent_copy;

/* Exercise actual own allocations and positive helper failures, without a
 * shared seam, another URL copy, or an artificial heap auth allocation. */
void *malloc(size_t size)
{
    if (url_size && size == url_size) ++url_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    if (fail_cause_after && fail_cause_text && !strcmp(text, fail_cause_text) && --fail_cause_after == 0) return NULL;
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(token1) == 36 && strlen(token2) == 38);
    CHECK(br_databrickstoken_init(NULL, &error) == -1 && error && !strcmp(error, "invalid DatabricksToken detector output"));
    free(error); error = NULL;
    CHECK(br_databrickstoken_init(NULL, NULL) == -1);
    CHECK(br_databrickstoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_databrickstoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 62 && detector->version == 0 && !strcmp(detector->name, "DatabricksToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Databricks is a cloud data platform. Databricks tokens can be used to authenticate and interact with Databricks services and APIs."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "databricks") && !strcmp(detector->keywords[1], "dapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, const char *domain, bool verified, const char *cause)
{
    size_t tlen = strlen(token), dlen = strlen(domain);
    CHECK(result->detector_type == 62 && !result->detector_name);
    CHECK(result->raw.len == tlen && !memcmp(result->raw.data, token, tlen));
    CHECK(result->raw_v2.len == tlen + dlen && !memcmp(result->raw_v2.data, token, tlen) && !memcmp(result->raw_v2.data + tlen, domain, dlen));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == tlen && !memcmp(json_object_get_string(part), token, tlen));
    CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == dlen && !memcmp(json_object_get_string(part), domain, dlen));
    CHECK(result->verified == verified && !result->verification_from_cache);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, br_slice input, const char *token, const char *domain)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (token && domain ? 1u : 0u) && !http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], token, domain, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], candidate[80], extended[39];
    snprintf(extended, sizeof(extended), "%s-7", token1);
    const struct { const char *suffix; int outcome; } suffixes[] = {
        {"", 0}, {"-7", 1}, {"-12", 0}, {"-1x", 0}, {"-", 0}, {"-x", 0},
        {"-\xd9\xa1", 0}, {"-1_", 0}, {"-7-9", 1}, {"x", -1}, {"_", -1}, {"0", -1},
    };
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s\n%s%s", domain1, token1, suffixes[i].suffix);
        extraction_case(detector, text(input), suffixes[i].outcome < 0 ? NULL : suffixes[i].outcome ? extended : token1, domain1);
    }
    const struct { const char *format; bool match; } tokens[] = {
        {"%s", true}, {"'%s'", true}, {"\xc3\xa9%s\xc3\xa9", true},
        {"x%s", false}, {"_%s", false}, {"%s_", false},
    };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", domain1);
        snprintf(input + at, sizeof(input) - at, tokens[i].format, token1);
        extraction_case(detector, text(input), tokens[i].match ? token1 : NULL, domain1);
    }
    memcpy(candidate, token1, sizeof(token1)); candidate[0] = 'D';
    snprintf(input, sizeof(input), "%s %s", candidate, domain1); extraction_case(detector, text(input), NULL, domain1);
    memcpy(candidate, token1, sizeof(token1)); candidate[12] = 'A';
    snprintf(input, sizeof(input), "%s %s", candidate, domain1); extraction_case(detector, text(input), NULL, domain1);
    memcpy(candidate, token1, sizeof(token1)); candidate[12] = 'g';
    snprintf(input, sizeof(input), "%s %s", candidate, domain1); extraction_case(detector, text(input), NULL, domain1);
    snprintf(input, sizeof(input), "%.35s %s", token1, domain1); extraction_case(detector, text(input), NULL, domain1);
    snprintf(candidate, sizeof(candidate), "dapi00000000000000000000000000000000");
    snprintf(input, sizeof(input), "%s %s", candidate, domain1); extraction_case(detector, text(input), candidate, domain1); /* No entropy filter. */
    const struct { const char *value, *capture; } domains[] = {
        {"synthetic.cloud.databricks.com", "synthetic.cloud.databricks.com"},
        {"a.b.gcp.databricks.com", "a.b.gcp.databricks.com"},
        {"adb-9.azuredatabricks.net", "adb-9.azuredatabricks.net"},
        {"a-.cloud.databricks.com", "a-.cloud.databricks.com"}, /* Source does not validate DNS labels. */
        {"a.cloud.databricks.com.evil", "a.cloud.databricks.com"},
        {"A.a.cloud.databricks.com", "a.cloud.databricks.com"},
        {"https://a.cloud.databricks.com:443/path", "a.cloud.databricks.com"},
        {"a.CLOUD.databricks.com", NULL}, {"a.cloud.Databricks.com", NULL}, {"a.cloud.databricks.COM", NULL},
        {"cloud.databricks.com", NULL}, {"azuredatabricks.net", NULL}, {"a..cloud.databricks.com", NULL},
        {"a.cloud.databricks.com_", NULL}, {"a.cloud.databricks.comx", NULL},
    };
    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); ++i) {
        snprintf(input, sizeof(input), "%s\n%s", token1, domains[i].value);
        extraction_case(detector, text(input), token1, domains[i].capture);
    }
    extraction_case(detector, text(token1), token1, NULL); /* Domain REQUIRED, no token-only fallback. */
    extraction_case(detector, text(domain1), NULL, domain1);
    extraction_case(detector, (br_slice){0}, NULL, NULL);
    int n = snprintf(input, sizeof(input), "\xff\n%s\n%s\n\xff", token1, domain1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, token1, domain1);
}

typedef struct {
    const char *const *tokens, *const *domains;
    size_t ntokens, ndomains;
    const char *agent, *borrowed_url, *borrowed_auth, *current_token, *current_domain;
    const br_scan_ctx *original;
    char *owned_error;
    bool clobber_error;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t pair = http->calls - 1;
    CHECK(ctx && pair < expected->ntokens * expected->ndomains);
    CHECK(!ctx->cancelled && !ctx->cancel_user && !ctx->deadline_monotonic_ms);
    CHECK(ctx->transport && ctx->transport->user == http);
    if (expected->original) {
        CHECK(ctx != expected->original && ctx->transport == expected->original->transport);
        CHECK(ctx->user_agent == expected->original->user_agent);
    }
    const char *token = expected->tokens[pair / expected->ndomains], *domain = expected->domains[pair % expected->ndomains];
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && request->detector_type == 62);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(strlen(request->url) == 8 + strlen(domain) + strlen(path));
    CHECK(!memcmp(request->url, "https://", 8) && !memcmp(request->url + 8, domain, strlen(domain)));
    CHECK(!strcmp(request->url + 8 + strlen(domain), "/api/2.0/preview/scim/v2/Me"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 7 + strlen(token) && !memcmp(auth, "Bearer ", 7) && !strcmp(auth + 7, token));
    CHECK(auth[7 + strlen(token)] == '\0');
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    expected->borrowed_url = request->url; expected->borrowed_auth = auth;
    expected->current_token = token; expected->current_domain = domain;
}

static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; expected_http *expected = http->user;
    if (expected) expected->owned_error = *error;
    return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(!memcmp(expected->borrowed_url, "https://", 8));
        CHECK(!memcmp(expected->borrowed_url + 8, expected->current_domain, strlen(expected->current_domain)));
        CHECK(!strcmp(expected->borrowed_url + 8 + strlen(expected->current_domain), path));
        CHECK(!strcmp(expected->borrowed_auth + 7, expected->current_token)); /* URL and stack auth survive release. */
        expected->borrowed_url = expected->borrowed_auth = NULL;
    }
    if (expected && expected->clobber_error && expected->owned_error) {
        expected->owned_error[0] = 'X'; /* Candidate cause must ALREADY be an independent copy. */
        expected->owned_error = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, send_request, release_response};
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void products_and_background(const br_detector *detector)
{
    char input[4096];
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n%s\n%s\n%s\n", domain1, domain2, domain1, domain3);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\n%s\n%s\n%s", token1, token2, token1);
    const char *tokens[] = {token1, token2}, *domains[] = {domain1, domain2, domain3};
    expected_http expected = {.tokens = tokens, .domains = domains, .ntokens = 2, .ndomains = 3, .agent = "TruffleHog databricks-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); size_t cancellations = 0;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "databricks-offline", .deadline_monotonic_ms = 1,
                       .cancelled = cancelled, .cancel_user = &cancellations}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == 6 && !http.calls && !http.releases && !cancellations);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i / 3], domains[i % 3], false, NULL);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6 && !cancellations);
    CHECK(ctx.deadline_monotonic_ms == 1 && ctx.cancelled == cancelled && ctx.cancel_user == &cancellations);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i / 3], domains[i % 3], true, NULL);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, at);
    CHECK(results.len == 6); /* NewRequest has a background context; NULL scan ctx is NOT a constructor skip. */
    for (size_t i = 0; i < results.len; ++i)
        check_result(&results.items[i], tokens[i / 3], domains[i % 3], false, "HTTP transport not installed");
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\n%s", token2, domain1);
    const char *tokens[] = {token2}, *domains[] = {domain1};
    expected_http expected = {.tokens = tokens, .domains = domains, .ntokens = 1, .ndomains = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error, *cause; bool verified; } cases[] = {
        {200, "ignored", NULL, true}, {401, "ignored", NULL, false}, {403, "", NULL, false},
        {199, NULL, "unexpected status code: 199", false}, {201, "ignored", "unexpected status code: 201", false},
        {204, NULL, "unexpected status code: 204", false}, {299, NULL, "unexpected status code: 299", false},
        {300, NULL, "unexpected status code: 300", false}, {404, "ignored", "unexpected status code: 404", false},
        {429, NULL, "unexpected status code: 429", false}, {500, NULL, "unexpected status code: 500", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], token2, domain1, cases[i].verified, cases[i].cause); br_results_clear(&results);
    }
    char echo[256]; snprintf(echo, sizeof(echo), "transport failed for token=%s host=%s token=%s", token2, domain1, token2);
    const char *causes[] = {echo, "context canceled", "net/http: nil Context", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        expected.clobber_error = true;
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = causes[i], .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], token2, domain1, false, causes[i] ? causes[i] : "HTTP transport failed");
        if (i == 0) CHECK(strstr(results.items[0].verification_error, token2) && strstr(results.items[0].verification_error, domain1) && !strstr(results.items[0].verification_error, "[REDACTED]"));
        br_results_clear(&results);
    }
}

static void setup_causes(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\n%s", token1, domain1);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .user_agent = "bad\r\nagent"}, {.transport = &transport}};
    const char *causes[] = {"HTTP transport not installed", "invalid HTTP user agent", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 2) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], token1, domain1, false, causes[i]); br_results_clear(&results);
    }
}

static void unbounded_domain(const br_detector *detector)
{
    const size_t label = 8192;
    char *domain = malloc(label + 64), *input = malloc(label + 192); CHECK(domain && input);
    memset(domain, 'a', label); strcpy(domain + label, ".cloud.databricks.com");
    snprintf(input, label + 192, "%s\n%s", token2, domain);
    const char *tokens[] = {token2}, *domains[] = {domain};
    expected_http expected = {.tokens = tokens, .domains = domains, .ntokens = 1, .ndomains = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport};
    url_size = 8 + strlen(domain) + sizeof(path); size_t before = url_allocations;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && url_allocations == before + 1);
    check_result(&results.items[0], token2, domain, true, NULL);
    br_results_clear(&results); free(input); free(domain); url_size = 0;
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    const char same_length_domain[] = "different.cloud.databricks.com";
    CHECK(strlen(same_length_domain) == strlen(domain1));
    char input[384]; snprintf(input, sizeof(input), "%s\n%s\n%s", token2, domain1, same_length_domain);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *tokens[] = {token2}, *domains[] = {domain1, same_length_domain};
    expected_http expected = {.tokens = tokens, .domains = domains, .ntokens = 1, .ndomains = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create DatabricksToken result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; http.response.status = 429;
    fail_cause_text = "unexpected status code: 429"; fail_cause_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set DatabricksToken verification error") && !fail_cause_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; http.response.status = 200;
    fail_alloc_size = 8 + strlen(domain1) + sizeof(path); fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate DatabricksToken request URL") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate DatabricksToken request URL") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 3 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = strlen(domain1) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append DatabricksToken result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], token2, domains[i], true, NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); products_and_background(detector); verification(detector); setup_causes(detector);
    unbounded_domain(detector); fatal_resources(detector);
    return test_finish("DatabricksToken direct unique products + regex fallback + background PUBLIC Bearer + unredacted causes + rollback");
}
