/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[65], key2[65];
static const char email1[] = "Alice@EXample.test", email2[] = "alice@example.test";
static size_t body_size, body_allocations, fail_alloc_size, fail_alloc_after;
static size_t fail_part_after, fail_environment_after;
static bool fail_agent_copy;

/* Target actual allocation and positive metadata failures, without adding
 * shared seams or bypassing the injected transport. */
void *malloc(size_t size)
{
    if (body_size && size == body_size) ++body_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) {
        fail_agent_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    if (fail_environment_after && !strcmp(name, "environment") && --fail_environment_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static size_t payload_size(const char *email)
{
    return strlen("{\"login_id\":\"") + strlen(email) + strlen("\",\"api_key\":\"") + 64 + 1;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_currencycloud_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CurrencyCloud detector output"));
    free(error); error = NULL;
    CHECK(br_currencycloud_init(NULL, NULL) == -1);
    CHECK(br_currencycloud_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_currencycloud_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 382 && detector->version == 0 && !strcmp(detector->name, "CurrencyCloud"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Currencycloud provides a global payments platform that allows businesses to make payments and manage currency risk. Currencycloud API keys can be used to access and manage these financial services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "currencycloud"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, int env)
{
    CHECK(result->detector_type == 382 && !result->detector_name && !result->verification_error);
    CHECK(result->raw.len == 64 && result->raw.data && !memcmp(result->raw.data, key, 64));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(!result->verification_from_cache && result->verified == (env >= 0));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 64 && !memcmp(json_object_get_string(part), key, 64));
    if (env < 0) CHECK(!result->extra_data);
    else {
        const char *expected = env == 0 ? "https://devapi.currencycloud.com" : "https://api.currencycloud.com";
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "environment", &part) && json_object_is_type(part, json_type_string));
        CHECK(!strcmp(json_object_get_string(part), expected));
    }
}

static void extraction_case(const br_detector *detector, br_slice input, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = body_allocations;
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (key ? 1u : 0u) && !http.calls && !http.releases && body_allocations == before);
    if (key) check_result(&results.items[0], key, -1);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[66];
    const struct { const char *format; bool match; } cases[] = {
        {"currencycloud %s", true}, {"CuRrEnCyClOuD '%s'", true}, {"preCurrencyCloudsuffix\r\n%s", true},
        {"%s currencycloud", false}, {"%s", false}, {"currencycloud%s", false},
        {"currencycloud x%s", false}, {"currencycloud _%s", false},
        {"currencycloud %sx", false}, {"currencycloud %s_", false},
        {"currencycloud .%s!", true}, {"currencycloud \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", email1);
        snprintf(input + at, sizeof(input) - at, cases[i].format, key1);
        extraction_case(detector, text(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, sizeof(key1)); changed[13] = 'A';
    snprintf(input, sizeof(input), "%s\ncurrencycloud %s", email1, changed); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "%s\ncurrencycloud %.63s", email1, key1); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "%s\ncurrencycloud %s0", email1, key1); extraction_case(detector, text(input), NULL);
    memset(changed, 'a', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "%s\ncurrencycloud %s", email1, changed); extraction_case(detector, text(input), changed);
    snprintf(input, sizeof(input), "currencycloud %s", key1); extraction_case(detector, text(input), NULL); /* Email required. */
    snprintf(input, sizeof(input), "currencycloud %s x@localhost", key1); extraction_case(detector, text(input), NULL);
    extraction_case(detector, (br_slice){0}, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            size_t at = (size_t)snprintf(input, sizeof(input), "%s\ncurrencycloud", email1);
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, sizeof(key1));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + 64}, gap == 40 ? key1 : NULL);
        }
    }
    /* Both patterns retain core go-re2 invalid-byte barriers, not a detector
     * whole-input UTF-8 error or normalization pass. */
    int n = snprintf(input, sizeof(input), "\xff%s\ncurrencycloud %s\n\xff", email1, key1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key1);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct { const char *key, *email; unsigned env; reply response; } request_step;
typedef struct {
    const request_step *steps; size_t count;
    const unsigned char *pair_body;
    br_slice borrowed_body;
    const char *agent;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && http->calls <= expected->count);
    const request_step *step = &expected->steps[http->calls - 1];
    const char *url = step->env == 0 ? "https://devapi.currencycloud.com/v2/authenticate/api" :
                                    "https://api.currencycloud.com/v2/authenticate/api";
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 382);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    CHECK(request->body.data && request->body.len == payload_size(step->email));
    size_t at = strlen("{\"login_id\":\"");
    CHECK(!memcmp(request->body.data, "{\"login_id\":\"", at));
    CHECK(!memcmp(request->body.data + at, step->email, strlen(step->email))); at += strlen(step->email);
    CHECK(!memcmp(request->body.data + at, "\",\"api_key\":\"", strlen("\",\"api_key\":\""))); at += strlen("\",\"api_key\":\"");
    CHECK(!memcmp(request->body.data + at, step->key, 64)); at += 64;
    CHECK(at + 1 == request->body.len && request->body.data[at] == '"'); /* NO closing brace, escaping or trailing NUL. */
    if (step->env == 0) expected->pair_body = request->body.data;
    else if (expected->pair_body) CHECK(expected->pair_body == request->body.data);
    expected->borrowed_body = request->body;
    http->response = (br_http_response){.status = step->response.status, .body = step->response.body,
                                       .body_error = step->response.read_error};
    http->send_rc = step->response.rc; http->send_error = step->response.send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_body.data) {
        CHECK(expected->borrowed_body.len && expected->borrowed_body.data[0] == '{');
        CHECK(expected->borrowed_body.data[expected->borrowed_body.len - 1] == '"');
        expected->borrowed_body = (br_slice){0};
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products_and_quoted_email(const br_detector *detector)
{
    char input[4096];
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n%s\n%s\n", email1, email1, email2);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\ncurrencycloud %s\ncurrencycloud %s\ncurrencycloud %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}, *emails[] = {email1, email2};
    br_results results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 6); /* Distant BARE emails, independent bytewise uniqueness; key-major occurrence products. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 2], -1);
    br_results_clear(&results);
    request_step steps[6];
    for (size_t i = 0; i < 6; ++i)
        steps[i] = (request_step){keys[i / 2], emails[i % 2], 0, {.status = 500, .body = text("prefixauth_tokensuffix")}};
    expected_http expected = {.steps = steps, .count = 6, .agent = "TruffleHog currencycloud-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "currencycloud-offline"};
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 2], 0);
    br_results_clear(&results);

    const char quoted[] = "\"Q\\\"u\x01\x7f\"@EXample.test";
    snprintf(input, sizeof(input), "x%s\ncurrencycloud %s", quoted, key1);
    request_step quoted_step = {key1, quoted, 0, {.status = 401, .body = text("auth_token")}};
    expected = (expected_http){.steps = &quoted_step, .count = 1, .agent = "TruffleHog"};
    http = (test_http){.inspect = inspect_request, .user = &expected}; transport = transport_for(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key1, 0); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\ncurrencycloud %s", email1, key1);
    static const unsigned char binary[] = {0xff, 0, 'a', 'u', 't', 'h', '_', 't', 'o', 'k', 'e', 'n', 0};
    const struct { reply replies[2]; int environment; } cases[] = {
        {{{.status = 500, .body = text("not-json:auth_token!")}, {0}}, 0},
        {{{.status = 401, .body = {binary, sizeof(binary)}}, {0}}, 0},
        {{{.status = 200, .body = text("Auth_Token")}, {.status = 401, .body = text("auth_token")}}, 1},
        {{{.status = 200, .body = text("auth_token"), .read_error = ""}, {.status = 500, .body = text("auth_token")}}, 1},
        {{{.status = 200, .body = text("auth_token"), .read_error = "read failed"}, {.status = 200, .body = text("auth_token"), .read_error = ""}}, -1},
        {{{.status = 200, .body = text("no token")}, {.status = 200, .body = text("auth-token")}}, -1},
        {{{.status = 200, .rc = 1, .body = text("auth_token"), .send_error = "net/http: nil Context"}, {.status = 500, .body = text("auth_token")}}, 1},
        {{{.rc = -1, .send_error = "out of memory constructing HTTP headers"}, {.rc = 1}}, -1},
    };
    body_size = payload_size(email1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        request_step steps[] = {{key1, email1, 0, cases[i].replies[0]}, {key1, email1, 1, cases[i].replies[1]}};
        size_t calls = cases[i].environment == 0 ? 1 : 2;
        expected_http expected = {.steps = steps, .count = calls, .agent = "TruffleHog"};
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; size_t before = body_allocations;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == calls && http.releases == calls && body_allocations == before + 1);
        check_result(&results.items[0], key1, cases[i].environment); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void contexts_and_setup(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\ncurrencycloud %s", email1, key1);
    size_t before = body_allocations;
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && body_allocations == before + 1); /* Construction BEFORE nil ctx; retain the outer finding. */
    check_result(&results.items[0], key1, -1); br_results_clear(&results);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; before = body_allocations;
        results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 2u : 0u) && body_allocations == before + 1);
        check_result(&results.items[0], key1, -1); br_results_clear(&results);
    }
    CHECK(cancellations == 2);
    /* Real shared setup/allocation +1 on devapi CONTINUES to api, not skip,
     * scan failure, diagnostic classification or candidate verification error. */
    request_step step = {key1, email1, 1, {.status = 500, .body = text("auth_token")}};
    expected_http expected = {.steps = &step, .count = 1, .agent = "TruffleHog"};
    http = (test_http){.inspect = inspect_request, .user = &expected}; transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; fail_agent_copy = true;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!fail_agent_copy && results.len == 1 && http.calls == 1 && http.releases == 2);
    check_result(&results.items[0], key1, 1); br_results_clear(&results);
}

static void unbounded_email(const br_detector *detector)
{
    const size_t local = 8192;
    char *email = malloc(local + 32), *input = malloc(local + 256); CHECK(email && input);
    memset(email, 'A', local); strcpy(email + local, "@EXample.test");
    snprintf(input, local + 256, "currencycloud %s\n%s", key1, email);
    request_step steps[] = {{key1, email, 0, {.status = 200}}, {key1, email, 1, {.status = 401, .body = text("auth_token")}}};
    expected_http expected = {.steps = steps, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; body_size = payload_size(email); size_t before = body_allocations;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2 && http.releases == 2 && body_allocations == before + 1);
    check_result(&results.items[0], key1, 1); br_results_clear(&results); free(input); free(email);
    body_size = payload_size(email1);
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
    char input[384]; snprintf(input, sizeof(input), "%s\n%s\ncurrencycloud %s", email1, email2, key1);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    /* Own resource errors win before constructor skips and environment logic. */
    size_t before = body_allocations; fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create CurrencyCloud result") && !fail_part_after && body_allocations == before);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = body_size; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate CurrencyCloud request body") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;

    request_step steps[] = {{key1, email1, 0, {.status = 500, .body = text("auth_token")}},
                            {key1, email2, 0, {.status = 401, .body = text("auth_token")}}};
    expected_http expected = {.steps = steps, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport};
    /* A positive environment insertion error on pair two is fatal BEFORE its
     * success break, rolling back only findings appended by this invocation. */
    fail_environment_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot add CurrencyCloud environment") && !fail_environment_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_alloc_size = body_size; fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate CurrencyCloud request body") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 65; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append CurrencyCloud result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key1, 0);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 64, 0); test_secret(key2, 64, 7);
    const br_detector *detector = descriptor();
    body_size = payload_size(email1);
    extraction(detector); products_and_quoted_email(detector); verification(detector);
    contexts_and_setup(detector); unbounded_email(detector); fatal_resources(detector);
    return test_finish("CurrencyCloud hidden-email products + literal malformed payload + ordered environments + binary token + rollback");
}
