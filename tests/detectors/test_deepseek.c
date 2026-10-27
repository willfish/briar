/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char token1[] = "sk-0123456789abcdefghijklmnopqrstuv";
static const char token2[] = "sk-vutsrqponmlkjihgfedcba9876543210";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_available_after, fail_duplicate_after;
static const char *fail_duplicate_text;
static bool fail_agent_copy;

/* Target real native/helper resources, including positive metadata and setter
 * failures, without adding a production JSON/auth seam or new dependencies. */
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
    if (fail_part_after && --fail_part_after == 0) return 1;
    if (fail_available_after && !strcmp(name, "is_available") && --fail_available_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(token1) == 35 && strlen(token2) == 35);
    CHECK(br_deepseek_init(NULL, &error) == -1 && error && !strcmp(error, "invalid DeepSeek detector output"));
    free(error); error = NULL;
    CHECK(br_deepseek_init(NULL, NULL) == -1);
    CHECK(br_deepseek_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_deepseek_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1026 && detector->version == 0 && !strcmp(detector->name, "DeepSeek"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DeepSeek is an artificial intelligence company that develops large language models (LLMs)"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "deepseek"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, const char *available, const char *cause)
{
    /* Reuse the complete default-field/secret-parts assertions, checking the
     * only optional provider field independently on the original finding. */
    br_result base = *result; base.extra_data = NULL;
    test_key_result(&base, 1026, token, "key");
    CHECK(result->verified == (available != NULL));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    if (!available) CHECK(!result->extra_data);
    else {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        br_json *value = NULL;
        CHECK(json_object_object_get_ex(result->extra_data, "is_available", &value) && json_object_is_type(value, json_type_string));
        CHECK(!strcmp(json_object_get_string(value), available)); /* STRING, not a JSON bool. */
    }
}

static void extraction_case(const br_detector *detector, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, NULL, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[37];
    const struct { const char *format; bool match; } cases[] = {
        {"deepseek %s", true}, {"DeEpSeEk:'%s'", true}, {"preDEEPSEEKsuffix\r\n%s", true},
        {"%s deepseek", false}, {"%s", false}, {"deepseek%s", false},
        {"deepseek x%s", false}, {"deepseek _%s", false}, {"deepseek %sx", false}, {"deepseek %s_", false},
        {"deepseek .%s!", true}, {"deepseek \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, token1);
        extraction_case(detector, text(input), cases[i].match ? token1 : NULL);
    }
    memcpy(changed, token1, sizeof(token1)); changed[0] = 'S';
    snprintf(input, sizeof(input), "deepseek %s", changed); extraction_case(detector, text(input), NULL);
    memcpy(changed, token1, sizeof(token1)); changed[8] = 'A';
    snprintf(input, sizeof(input), "deepseek %s", changed); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "deepseek %.34s", token1); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "deepseek %sa", token1); extraction_case(detector, text(input), NULL);
    memcpy(changed, "sk-", 3); memset(changed + 3, 'z', 32); changed[35] = '\0';
    snprintf(input, sizeof(input), "deepseek %s", changed); extraction_case(detector, text(input), changed); /* Lower ALNUM, not hex or entropy-filtered. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "deepseek", 8); size_t at = 8;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, token1, sizeof(token1));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + 35}, gap == 40 ? token1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\ndeepseek %s\n\xff", token1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, token1);
    extraction_case(detector, (br_slice){0}, NULL);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *tokens; size_t count;
    const reply *replies;
    const char *agent, *borrowed_auth, *current_token;
    const br_scan_ctx *original;
    char *owned_error;
    bool clobber_error;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *token = expected->tokens[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.deepseek.com/user/balance"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1026);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    const char *auth = request->headers[1].value;
    CHECK(strlen(auth) == 42 && auth[42] == '\0' && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, token, 35));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    expected->borrowed_auth = auth; expected->current_token = token;
    if (expected->replies) {
        const reply *r = &expected->replies[http->calls - 1];
        http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error};
        http->send_rc = r->rc; http->send_error = r->send_error;
    }
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
    if (expected && expected->borrowed_auth) {
        CHECK(!memcmp(expected->borrowed_auth, "Bearer ", 7) && !memcmp(expected->borrowed_auth + 7, expected->current_token, 35));
        CHECK(expected->borrowed_auth[42] == '\0'); /* The complete stack header survives release. */
        expected->borrowed_auth = NULL;
    }
    if (expected && expected->clobber_error && expected->owned_error) {
        expected->owned_error[0] = 'X'; /* Cause must ALREADY be independently copied, without redaction. */
        expected->owned_error = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, send_request, release_response};
}

static void verification_case(const br_detector *detector, reply response, const char *available, const char *cause)
{
    char input[128]; int n = snprintf(input, sizeof(input), "deepseek %s", token1);
    const char *tokens[] = {token1};
    expected_http expected = {.tokens = tokens, .count = 1, .replies = &response, .agent = "TruffleHog", .clobber_error = true};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = {0}; char *error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    if (rc != 0) fprintf(stderr, "response=%.*s read_error=%s scan_error=%s\n", (int)response.body.len,
                         response.body.data ? (const char *)response.body.data : "", response.read_error ? response.read_error : "(none)", error ? error : "(none)");
    CHECK(rc == 0 && !error);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], token1, available, cause); br_results_clear(&results);
}

static void unique_tokens_and_nil_context(const br_detector *detector)
{
    char input[256]; int n = snprintf(input, sizeof(input), "deepseek %s\nDEEPSEEK %s\ndeepseek %s", token1, token2, token1);
    const char *tokens[] = {token1, token2};
    br_results results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i], NULL, NULL);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(results.len == 2); /* Nil context RETAINS false findings, not DataGov-style skips. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], tokens[i], NULL, "net/http: nil Context");
    br_results_clear(&results);
    const reply replies[] = {{.status = 200, .body = text("{}")}, {.status = 200, .body = text("{\"is_available\":true}")}};
    expected_http expected = {.tokens = tokens, .count = 2, .replies = replies, .agent = "TruffleHog deepseek-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "deepseek-offline"}; expected.original = &ctx;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token1, "false", NULL); check_result(&results.items[1], token2, "true", NULL);
    br_results_clear(&results);
}

static void typed_json(const br_detector *detector)
{
    const struct { const char *body, *available, *cause; } cases[] = {
        {"null", "false", NULL}, {"{}", "false", NULL}, {"{\"is_available\":false}", "false", NULL},
        {"{\"is_available\":true}", "true", NULL}, {"{\"is_available\":null}", "false", NULL},
        {"{\"is_available\":true,\"is_available\":null}", "true", NULL},
        {"{\"is_available\":true,\"is_available\":false}", "false", NULL},
        {"{\"is_available\":false,\"IS_AVAILABLE\":true}", "true", NULL},
        {"{\"\\u0069s_available\":true}", "true", NULL}, {"{\"i\\u017f_available\":true}", "true", NULL},
        {"{\"i\xc5\xbf_available\":true}", "true", NULL},
        {"{\"unknown\":\"\xce\xbb\",\"is_available\":true}", "true", NULL},
        {"{\"is_available\":\"\xce\xbb\"}", NULL, "json: cannot unmarshal string into Go struct field response.is_available of type bool"},
        {"{\"IsAvailable\":true}", "false", NULL}, /* Tag has an underscore; Go field spelling is not another alias. */
        {"{\"is_available\":\"bad\",\"is_available\":true}", NULL, "json: cannot unmarshal string into Go struct field response.is_available of type bool"},
        {"{\"is_available\":1,\"is_available\":\"bad\",\"is_available\":false}", NULL, "json: cannot unmarshal number into Go struct field response.is_available of type bool"},
        {"{\"is_available\":{},\"is_available\":true}", NULL, "json: cannot unmarshal object into Go struct field response.is_available of type bool"},
        {"{\"is_available\":[]}", NULL, "json: cannot unmarshal array into Go struct field response.is_available of type bool"},
        {"{\"unknown\":184467440737095516160000000000000000,\"other\":[1e9999,{\"x\":-9223372036854775809}],\"is_available\":true}", "true", NULL},
        {"{\"is_available\":1e9999}", NULL, "json: cannot unmarshal number into Go struct field response.is_available of type bool"},
        {" {\"is_available\":true} {broken trailing document", "true", NULL}, {"null {\"is_available\":true}", "false", NULL},
        {"[]", NULL, "json: cannot unmarshal array into Go value of type deepseek.response"},
        {"true", NULL, "json: cannot unmarshal bool into Go value of type deepseek.response"},
        {"\"text\"", NULL, "json: cannot unmarshal string into Go value of type deepseek.response"},
        {"1e9999", NULL, "json: cannot unmarshal number into Go value of type deepseek.response"},
        {"", NULL, "EOF"}, {"{", NULL, "unexpected EOF"},
        {"{\"is_available\":}", NULL, "invalid character '}' looking for beginning of value"},
        {"{\"is_available\":\"bad\",\"unknown\":}", NULL, "invalid character '}' looking for beginning of value"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        verification_case(detector, (reply){.status = 200, .body = text(cases[i].body)}, cases[i].available, cases[i].cause);
    verification_case(detector, (reply){.status = 200, .body = text("{}"), .read_error = "ignored after complete object"}, "false", NULL);
    verification_case(detector, (reply){.status = 200, .body = text("{\"is_available\":true"), .read_error = "synthetic read failure"}, NULL, "synthetic read failure");
    verification_case(detector, (reply){.status = 200, .read_error = ""}, NULL, "");
}

static void statuses_and_causes(const br_detector *detector)
{
    const int statuses[] = {201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        verification_case(detector, (reply){.status = statuses[i], .body = text("{\"is_available\":\"bad\"}"), .read_error = "ignored"},
                          NULL, statuses[i] == 401 ? NULL : cause);
    }
    char echo[160]; snprintf(echo, sizeof(echo), "synthetic Do cause token=%s again=%s", token1, token1);
    verification_case(detector, (reply){.status = 200, .body = text("{}"), .rc = 1, .send_error = echo}, NULL, echo);
    verification_case(detector, (reply){.status = 200, .rc = 1}, NULL, "HTTP transport failed");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_causes(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "deepseek %s", token1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, (size_t)n);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], token1, NULL, causes[i]); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
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
    char input[256]; int n = snprintf(input, sizeof(input), "deepseek %s\ndeepseek %s", token1, token2);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *tokens[] = {token1, token2};
    reply replies[] = {{.status = 200, .body = text("{}")}, {.status = 200, .body = text("{}")}};
    expected_http expected = {.tokens = tokens, .count = 2, .replies = replies, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create DeepSeek result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_duplicate_text = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set DeepSeek verification error") && !fail_duplicate_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_available_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot add DeepSeek is_available metadata") && !fail_available_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    /* The FIRST cause allocation is an owned JSON +1 cause; failure is -1.
     * The SECOND is the real sanitized setter's positive +1 resource return. */
    replies[1].body = text("{"); http.calls = http.releases = 0;
    fail_duplicate_text = "unexpected EOF"; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode DeepSeek verification response") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set DeepSeek verification error") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;

    /* Failure of the actual first-document validation shadow is fatal. */
    const char huge[] = "{\"is_available\":\"bad\",\"unknown\":1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901}";
    replies[1].body = text(huge); http.calls = http.releases = 0;
    fail_alloc_size = sizeof(huge); fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode DeepSeek verification response") && !fail_alloc_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    const char *number = strstr(huge, "1234567890"); CHECK(number);
    /* Validated children decode original bytes without another full shadow.
     * The earlier ordinary type cause survives the later unknown huge value. */
    http.calls = http.releases = 0; fail_alloc_size = strlen(number) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == 0 && !error);
    CHECK(fail_alloc_after == 1 && http.calls == 2 && http.releases == 2 && results.len == 3);
    fail_alloc_after = 0;
    check_result(&results.items[1], token1, "false", NULL);
    check_result(&results.items[2], token2, NULL, "json: cannot unmarshal string into Go struct field response.is_available of type bool");
    while (results.len > 1) br_result_clear(&results.items[--results.len]);
    check_prior(&results, prior);
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 36; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append DeepSeek result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    replies[1].body = text("{\"is_available\":true}"); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token1, "false", NULL); check_result(&results.items[1], token2, "true", NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); unique_tokens_and_nil_context(detector); typed_json(detector); statuses_and_causes(detector);
    setup_causes(detector); fatal_resources(detector);
    return test_finish("DeepSeek unique tokens + typed first-document bool + sticky errors + unredacted causes + rollback");
}
