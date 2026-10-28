/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char token1[41], token2[41];
static const char base_url[] = "https://fetchrss.com/api/v1/feed/list?auth=";
static const char default_cause[] = "unexpected error: [code=0, message=]";
static const char nul_error[] = "unsupported: Fetchrss diagnostic Message contains NUL; ABI1 error strings cannot represent it";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate_text;
static bool fail_agent_copy;

/* Actual capture/finding/JSON/cause/setter resources; no URL/formatter seam. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    if (fail_duplicate_after && fail_duplicate_text && !strcmp(text, fail_duplicate_text) && --fail_duplicate_after == 0) return NULL;
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(intptr_t) == 8 && strlen(token1) == 40 && strlen(token2) == 40 && strlen(base_url) == 43);
    CHECK(br_fetchrss_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Fetchrss detector output"));
    free(error); error = NULL;
    CHECK(br_fetchrss_init(NULL, NULL) == -1);
    CHECK(br_fetchrss_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_fetchrss_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 592 && detector->version == 0 && !strcmp(detector->name, "Fetchrss"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "FetchRSS is a service used to convert web content into RSS feeds. FetchRSS API keys can be used to manage and access these feeds."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "fetchrss"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, bool verified, const char *cause)
{
    test_key_result(result, 592, token, "key");
    CHECK(result->raw.len == 40 && result->verified == verified && !result->verification_from_cache);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 40);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected && (results.items[0].raw.len != strlen(expected) || memcmp(results.items[0].raw.data, expected, strlen(expected))))
        fprintf(stderr, "extraction input=%.*s expected=%s actual=%.*s\n", (int)len, input ? (const char *)input : "", expected, (int)results.items[0].raw.len, results.items[0].raw.data);
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[41];
    const struct { const char *format; bool matches; } cases[] = {
        {"fetchrss '%s'", true}, {"FETCHrss=%s", true}, {"prefetchrsssuffix:%s", true},
        {"fetchrss\r\n%s", true}, {"fetchrss\r%s", true}, {"fetchrss\n%s", true},
        {"%s", false}, {"%s fetchrss", false}, {"fetch rss %s", false}, {"fetchrss%s", false},
        {"fetchrss x%s", false}, {"fetchrss _%s", false}, {"fetchrss %s_", false}, {"fetchrss %s9", false},
        {"fetchrss %.39s", false}, {"fetchrss \xc3\xa9%s\xc3\xa9", true}, {"fetchrss %s.more", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, token1); extraction_case(detector, input, strlen(input), cases[i].matches ? token1 : NULL);
    }
    const char invalid[] = "_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, token1, sizeof(changed)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "fetchrss %s", changed); extraction_case(detector, input, strlen(input), NULL); /* Dot is literal alphabet, not wildcard. */
    }
    memcpy(changed, token1, sizeof(changed)); changed[0] = '.';
    snprintf(input, sizeof(input), "fetchrss %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fetchrss X%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, token1, sizeof(changed)); changed[39] = '.';
    snprintf(input, sizeof(input), "fetchrss %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fetchrss %sX", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, 'a', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "fetchrss %s", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, '.', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "fetchrss%s%s", changed, token1); extraction_case(detector, input, strlen(input), changed); /* Keyword word -> dot, then dot -> token: the dot run itself captures before prefix padding. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "fetchrss", 8); size_t at = 8;
            for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = ':'; }
            memcpy(input + at, token1, 40); at += 40; extraction_case(detector, input, at, gap == 40 ? token1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "fetchrss%c%s", 0, token1); extraction_case(detector, input, (size_t)n, token1);
    n = snprintf(input, sizeof(input), "\xff\nfetchrss %s\n\xff", token1); extraction_case(detector, input, (size_t)n, token1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *tokens; size_t count; const reply *replies;
    const char *agent, *borrowed_url, *current_token; const br_scan_ctx *original;
    char *owned_error; bool clobber_error;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *token = expected->tokens[http->calls - 1]; const reply *r = &expected->replies[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == 83 && !memcmp(request->url, base_url, 43));
    CHECK(!memcmp(request->url + 43, token, 41));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 592);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, expected->agent));
    CHECK(!expected->borrowed_url); expected->borrowed_url = request->url; expected->current_token = token;
    http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error}; http->send_rc = r->rc; http->send_error = r->send_error;
}

static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; expected_http *expected = http->user; expected->owned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 83 && !memcmp(expected->borrowed_url, base_url, 43));
        CHECK(!memcmp(expected->borrowed_url + 43, expected->current_token, 41)); expected->borrowed_url = NULL;
    }
    if (expected && expected->owned_error && expected->clobber_error) expected->owned_error[0] = 'X';
    if (expected) expected->owned_error = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_request, release_response}; }

static void verification_case(const br_detector *detector, reply r, bool verified, const char *cause)
{
    char input[64]; snprintf(input, sizeof(input), "fetchrss %s", token1);
    const char *tokens[] = {token1}; expected_http expected = {.tokens = tokens, .count = 1, .replies = &r, .agent = "TruffleHog", .clobber_error = true};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_url); check_result(&results.items[0], token1, verified, cause); br_results_clear(&results);
}

static void unique_and_nil_context(const br_detector *detector)
{
    char variant[41], input[256]; memcpy(variant, token1, sizeof(variant)); variant[5] = 'a';
    snprintf(input, sizeof(input), "fetchrss %s\nFETCHRSS %s\nfetchrss %s\nfetchrss %s", token1, token2, token1, variant);
    const char *tokens[] = {token1, token2, variant};
    const reply replies[] = {{.status = 200, .body = text("{\"success\":true}")}, {.status = 200, .body = text("{\"error\":{\"code\":401}}")}, {.status = 200, .body = text("{}")} };
    expected_http expected = {.tokens = tokens, .count = 3, .replies = replies, .agent = "TruffleHog fetchrss-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "fetchrss-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], false, NULL);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        check_result(&results.items[0], token1, true, NULL); check_result(&results.items[1], token2, false, NULL); check_result(&results.items[2], variant, false, default_cause); br_results_clear(&results);
    }
    http.calls = http.releases = 0; results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], false, "net/http: nil Context");
    br_results_clear(&results);
}

static void typed_response(const br_detector *detector)
{
    const struct { const char *body; bool verified; const char *cause; } cases[] = {
        {"{\"success\":true}", true, NULL}, {"{\"error\":{\"code\":401}}", false, NULL}, {"{}", false, default_cause}, {"null", false, default_cause},
        {"{\"success\":false,\"error\":{\"code\":500,\"message\":\"bad\"}}", false, "unexpected error: [code=500, message=bad]"},
        {"{\"success\":true,\"error\":{\"message\":2}}", false, "json: cannot unmarshal number into Go struct field .error.message of type string"},
        {"{\"success\":true,\"error\":{\"code\":\"401\"}}", false, "json: cannot unmarshal string into Go struct field .error.code of type int"},
        {"{\"success\":true,\"error\":[]}", false, "json: cannot unmarshal array into Go struct field response.error of type struct { Message string \"json:\\\"message\\\"\"; Code int \"json:\\\"code\\\"\" }"},
        {"{\"success\":\"bad\",\"success\":true}", false, "json: cannot unmarshal string into Go struct field response.success of type bool"},
        {"{\"error\":{\"message\":true},\"error\":{\"message\":\"fixed\",\"code\":401}}", false, "json: cannot unmarshal bool into Go struct field .error.message of type string"},
        {"{\"success\":true,\"success\":null,\"error\":null}", true, NULL},
        {"{\"error\":{\"message\":\"first\",\"code\":500},\"ERROR\":{\"message\":null,\"code\":null}}", false, "unexpected error: [code=500, message=first]"},
        {"{\"error\":{\"message\":\"first\",\"code\":500},\"error\":{\"code\":401},\"error\":null}", false, NULL},
        {"{\"Success\":true,\"unknown\":184467440737095516160000000000000000,\"error\":{\"unknown\":[1e9999,{\"x\":-9223372036854775809}]}}", true, NULL},
        {"{\"\\u017fuccess\":true}", true, NULL}, {"{\"\xc5\xbfuccess\":true}", true, NULL},
        {"{\"error\":{\"me\\u017f\\u017fage\":\"folded\",\"CoDe\":500}}", false, "unexpected error: [code=500, message=folded]"},
        {"{\"error\":{\"code\":9223372036854775807,\"message\":\"max\"}}", false, "unexpected error: [code=9223372036854775807, message=max]"},
        {"{\"error\":{\"code\":-9223372036854775808}}", false, "unexpected error: [code=-9223372036854775808, message=]"},
        {"{\"error\":{\"code\":-0}}", false, default_cause},
        {"{\"error\":{\"code\":401.0}}", false, "json: cannot unmarshal number 401.0 into Go struct field .error.code of type int"},
        {"{\"error\":{\"code\":4.01e2}}", false, "json: cannot unmarshal number 4.01e2 into Go struct field .error.code of type int"},
        {"{\"error\":{\"code\":9223372036854775808},\"error\":{\"code\":401}}", false, "json: cannot unmarshal number 9223372036854775808 into Go struct field .error.code of type int"},
        {"{\"error\":{\"code\":-9223372036854775809}}", false, "json: cannot unmarshal number -9223372036854775809 into Go struct field .error.code of type int"},
        {"{\"error\":{\"code\":1e9999}}", false, "json: cannot unmarshal number 1e9999 into Go struct field .error.code of type int"},
        {"{\"error\":{\"message\":\"\\u03bb \\\"quoted\\\" \\\\raw\\nnext\",\"code\":500}}", false, "unexpected error: [code=500, message=\xce\xbb \"quoted\" \\raw\nnext]"},
        {"{\"success\":true,\"error\":{\"message\":\"a\\u0000b\"}}", true, NULL},
        {"{\"error\":{\"code\":401,\"message\":\"a\\u0000b\"}}", false, NULL},
        {"{\"success\":true} {broken trailing", true, NULL}, {"null {\"success\":true}", false, default_cause},
        {"[]", false, "json: cannot unmarshal array into Go value of type fetchrss.response"},
        {"true", false, "json: cannot unmarshal bool into Go value of type fetchrss.response"},
        {"\"text\"", false, "json: cannot unmarshal string into Go value of type fetchrss.response"},
        {"", false, "EOF"}, {"{", false, "unexpected EOF"}, {"{\"success\":}", false, "invalid character '}' looking for beginning of value"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verification_case(detector, (reply){.status = 200, .body = text(cases[i].body)}, cases[i].verified, cases[i].cause);
    verification_case(detector, (reply){.status = 200, .body = text("{\"success\":true}"), .read_error = "ignored after first object"}, true, NULL);
    verification_case(detector, (reply){.status = 200, .body = text("{\"success\":true}"), .read_error = ""}, true, NULL);
    verification_case(detector, (reply){.status = 200, .body = text("{\"success\":true"), .read_error = "synthetic Reader failure"}, false, "synthetic Reader failure");
    verification_case(detector, (reply){.status = 200, .read_error = ""}, false, "");
}

static void causes_and_long_message(const br_detector *detector)
{
    const int statuses[] = {199, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        verification_case(detector, (reply){.status = statuses[i], .body = text("{\"success\":true}"), .read_error = "ignored"}, false, cause);
    }
    char echo[128]; snprintf(echo, sizeof(echo), "Do token=%s again=%s", token1, token1);
    verification_case(detector, (reply){.status = 200, .rc = 1, .send_error = echo}, false, echo); /* ZERO secrets, even token echoes remain literal. */
    verification_case(detector, (reply){.status = 200, .rc = 1}, false, "HTTP transport failed");
    const size_t length = 8192; char *message = malloc(length + 1), *body = malloc(length + 128), *wanted = malloc(length + 128); CHECK(message && body && wanted);
    memset(message, 'z', length); memcpy(message + 4000, token1, 40); message[length] = '\0';
    snprintf(body, length + 128, "{\"error\":{\"code\":500,\"message\":\"%s\"}}", message);
    snprintf(wanted, length + 128, "unexpected error: [code=500, message=%s]", message);
    verification_case(detector, (reply){.status = 200, .body = text(body)}, false, wanted); free(message); free(body); free(wanted);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_causes(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "fetchrss %s", token1); test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], token1, false, causes[i]); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
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

static void fatal_resources_and_nul(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "fetchrss %s\nfetchrss %s", token1, token2); br_slice data = text(input);
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *tokens[] = {token1, token2}; reply replies[] = {{.status = 200, .body = text("{\"success\":true}")}, {.status = 200, .body = text("{}")}};
    expected_http expected = {.tokens = tokens, .count = 2, .replies = replies, .agent = "TruffleHog"}; test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fetchrss result") && !fail_part_after); check_prior(&results, prior); free(error); error = NULL;
    fail_duplicate_text = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot set Fetchrss verification error") && !fail_duplicate_after); check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Fetchrss result") && !fail_part_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{"); http.calls = http.releases = 0; fail_duplicate_text = "unexpected EOF"; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode Fetchrss verification response") && !fail_duplicate_after && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{\"success\":true,\"error\":{\"message\":false}}"); http.calls = http.releases = 0;
    fail_duplicate_text = "json: cannot unmarshal bool into Go struct field .error.message of type string"; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode Fetchrss verification response") && !fail_duplicate_after && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL;
    const char huge[] = "{\"success\":true,\"unknown\":1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901}";
    replies[1].body = text(huge); http.calls = http.releases = 0; fail_alloc_size = sizeof(huge); fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode Fetchrss verification response") && !fail_alloc_after && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{}"); http.calls = http.releases = 0; fail_alloc_size = sizeof(default_cause); fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate Fetchrss diagnostic cause") && !fail_alloc_after && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_duplicate_text = default_cause; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set Fetchrss verification error") && !fail_duplicate_after && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{\"error\":{\"code\":500,\"message\":\"a\\u0000b\"}}"); http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, nul_error) && http.calls == 2 && http.releases == 2); check_prior(&results, prior); free(error); error = NULL; /* NUL only on THIS diagnostic branch is explicit fatal; earlier verified addition rolls back. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 41; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Fetchrss result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    replies[1].body = text("{\"success\":true}"); http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token1, true, NULL); check_result(&results.items[1], token2, true, NULL); br_results_clear(&results);
}

int main(void)
{
    test_secret(token1, 40, 0); test_secret(token2, 40, 7); token1[5] = 'A'; token1[12] = '.'; token1[39] = 'Z'; token2[5] = 'G'; token2[20] = '.'; token2[39] = 'K';
    const br_detector *detector = descriptor(); extraction(detector); unique_and_nil_context(detector); typed_response(detector); causes_and_long_message(detector); setup_causes(detector); fatal_resources_and_nul(detector);
    return test_finish("Fetchrss typed first-document response + zero-secret causes");
}
