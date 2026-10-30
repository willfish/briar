/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_json.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

int br_lob_init(const br_detector **out, char **error);

/* Reuse named-test seams, preserving actual HTTP preparation and JSON codecs. */
#define br_result_set_verification_error lob_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#define br_gcp_json_text lob_real_json_text
#include "../../src/detectors/gcp_json.c"
#undef br_gcp_json_text

static const char live_key[] = "live_0123456789abcdef0123456789abcdef012";
static const char test_key[] = "test_fedcba9876543210fedcba9876543210fed";
static char auth_live[64], auth_test[64];
static size_t fail_size, fail_after, fail_key_after, fail_env_after, fail_setter_after, fail_projection_after;
static size_t failed_allocations, setter_calls, projection_calls;
static const char *fail_strdup_text;
static size_t fail_strdup_after;
static bool fail_agent, fail_cause_after_projection;
static const br_detector *detector;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t original_len, setters_before;
    const char *borrowed_auth, *fixture;
    size_t fixture_len;
    char response_storage[1024];
    bool expected_verified, poison_body, release_per_finding;
} script;
static script *active;

void *malloc(size_t size)
{
    if (size == fail_size && fail_after && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if ((fail_agent && !strcmp(text, "TruffleHog")) ||
        (fail_strdup_after && fail_strdup_text && !strcmp(text, fail_strdup_text) && --fail_strdup_after == 0)) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if ((!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) ||
        (!strcmp(name, "environment") && fail_env_after && --fail_env_after == 0)) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_gcp_json_text(br_json *value, br_slice *out, br_bytes *repair, char **error)
{
    ++projection_calls;
    if (fail_projection_after && --fail_projection_after == 0) {
        if (error) *error = strdup("synthetic positive Lob string projection failure");
        return 1;
    }
    int rc = lob_real_json_text(value, out, repair, error);
    if (!rc && fail_cause_after_projection) {
        fail_cause_after_projection = false;
        fail_size = strlen("unexpected error code: <") + out->len + sizeof("> in the API response body");
        fail_after = 1;
    }
    return rc;
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    CHECK(!secrets && !count); /* Source deliberately supplies no redaction list. */
    if (active) {
        size_t expected_releases = active->release_per_finding ? setter_calls - active->setters_before + 1 : 0;
        CHECK(active->http.releases == expected_releases && !active->borrowed_auth);
        CHECK(result->verified == active->expected_verified);
        CHECK(active->out && active->out->len == active->original_len + setter_calls - active->setters_before);
    }
    ++setter_calls;
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return lob_real_setter(result, cause, secrets, count);
}

static void check_result(const br_result *result, const char *key, bool verified, const char *cause)
{
    CHECK(result->detector_type == 490 && result->raw.len == 40 && !memcmp(result->raw.data, key, 40));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set && !result->verification_from_cache);
    br_json *part = NULL, *environment = NULL;
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 40 && !memcmp(json_object_get_string(part), key, 40));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "environment", &environment) && json_object_is_type(environment, json_type_string));
    CHECK(json_object_get_string_len(environment) == 4 && !memcmp(json_object_get_string(environment), key, 4));
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static const char *result_key(const br_result *result)
{
    if (result->raw.len == 40 && !memcmp(result->raw.data, live_key, 40)) return live_key;
    CHECK(result->raw.len == 40 && !memcmp(result->raw.data, test_key, 40));
    return test_key;
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx == &s->ctx && http->calls == http->releases + 1 && !s->borrowed_auth);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.lob.com/v1/us_verifications"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 490);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, auth_live) || !strcmp(request->headers[0].value, auth_test));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog lob-offline"));
    /* Borrow provider auth only, never the prepared header-array/request/UA. */
    s->borrowed_auth = request->headers[0].value;
    if (s->fixture) {
        CHECK(s->fixture_len < sizeof(s->response_storage));
        memcpy(s->response_storage, s->fixture, s->fixture_len);
        http->response.body = (br_slice){(const unsigned char *)s->response_storage, s->fixture_len};
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(!strcmp(s->borrowed_auth, auth_live) || !strcmp(s->borrowed_auth, auth_test));
        s->borrowed_auth = NULL;
    } else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    CHECK(s->out && s->out->len == s->original_len + setter_calls - s->setters_before);
    if (s->poison_body) memset(s->response_storage, '!', s->fixture_len);
    test_http_release(user, response);
}

static void setup(script *s, int status, const char *body, const char *read_error, bool verified)
{
    *s = (script){.fixture = body, .fixture_len = body ? strlen(body) : 0, .expected_verified = verified, .poison_body = true};
    s->http = (test_http){.response = {.status = status, .body_error = read_error}, .inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "lob-offline"};
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out; s->original_len = out->len; s->setters_before = setter_calls;
    s->release_per_finding = ctx && ctx->transport && ctx->transport->release;
    active = s;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    active = NULL; s->out = NULL;
    return rc;
}

static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}

static void descriptor_and_extraction(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(live_key) == 40 && strlen(test_key) == 40);
    char plain[42]; memcpy(plain, live_key, 40); plain[40] = ':'; plain[41] = 0;
    memcpy(auth_live, "Basic ", 6); CHECK(EVP_EncodeBlock((unsigned char *)auth_live + 6, (const unsigned char *)plain, 41) == 56);
    memcpy(plain, test_key, 40); memcpy(auth_test, "Basic ", 6); CHECK(EVP_EncodeBlock((unsigned char *)auth_test + 6, (const unsigned char *)plain, 41) == 56);
    char *error = NULL; const br_detector *again = NULL;
    CHECK(br_lob_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Lob detector output")); free(error);
    CHECK(br_lob_init(NULL, NULL) != 0);
    CHECK(br_lob_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_lob_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 490 && detector->version == 0 && !strcmp(detector->name, "Lob") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Lob is a service for automating the creation and sending of letters, checks, and postcards. Lob API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "live_") && !strcmp(detector->keywords[1], "test_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    char input[256], changed[41];
    const char *formats[] = {"%s", "'%s'", "lob %s", "%s lob", "-%s-", "\xc3\xa9%s\xc3\xa9", "\xff %s \xfe", "\t%s\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(*formats); ++i) {
        script s; setup(&s, 422, NULL, NULL, true); size_t before = setter_calls;
        snprintf(input, sizeof(input), formats[i], live_key);
        br_results out = run(&s, &s.ctx, false, input);
        CHECK(out.len == 1 && !s.http.calls && !s.http.releases && setter_calls == before);
        check_result(&out.items[0], live_key, false, NULL); br_results_clear(&out);
    }
    const char *reject[] = {"x%s", "_%s", "%sx", "%s_", "%s0", "%.39s"};
    for (size_t i = 0; i < sizeof(reject) / sizeof(*reject); ++i) {
        snprintf(input, sizeof(input), reject[i], live_key);
        br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    }
    const char invalid[] = {'A', 'g', '-', '_', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, live_key, sizeof(changed)); changed[12] = invalid[i];
        br_results out = test_scan(detector, NULL, false, changed, 40); CHECK(!out.len); br_results_clear(&out);
    }
    memcpy(changed, live_key, sizeof(changed)); changed[0] = 'L';
    br_results out = test_scan(detector, NULL, false, changed, 40); CHECK(!out.len); br_results_clear(&out);
    snprintf(input, sizeof(input), "live_pub_%.31s test_pub_%.31s live_%.31s", live_key + 5, test_key + 5, live_key + 5);
    out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s %s %s", test_key, live_key, live_key, test_key);
    script s; setup(&s, 422, NULL, NULL, true); size_t before = setter_calls;
    out = run(&s, NULL, false, input);
    CHECK(out.len == 2 && !s.http.calls && !s.http.releases && setter_calls == before);
    bool seen_live = false, seen_test = false;
    for (size_t i = 0; i < out.len; ++i) {
        const char *key = result_key(&out.items[i]);
        CHECK(key == live_key ? !seen_live : !seen_test);
        if (key == live_key) seen_live = true; else seen_test = true;
        check_result(&out.items[i], key, false, NULL);
    }
    CHECK(seen_live && seen_test); br_results_clear(&out);
    out = run(&s, &s.ctx, true, input); CHECK(out.len == 2 && s.http.calls == 2 && s.http.releases == 2 && setter_calls == before + 2);
    for (size_t i = 0; i < out.len; ++i) check_result(&out.items[i], result_key(&out.items[i]), true, NULL);
    br_results_clear(&out);
    memcpy(input, live_key, 40); input[40] = 0; memcpy(input + 41, test_key, 40);
    out = test_scan(detector, NULL, false, input, 81); CHECK(out.len == 2); br_results_clear(&out);
    out = test_scan(detector, NULL, false, NULL, 0); CHECK(!out.len); br_results_clear(&out);
}

static void ordinary_verification(void)
{
    const struct { int status; bool verified; const char *cause; } statuses[] = {
        {422, true, NULL}, {401, false, NULL}, {200, false, "unexpected status code: 200"},
        {204, false, "unexpected status code: 204"}, {299, false, "unexpected status code: 299"},
        {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, statuses[i].status, "not JSON", "ignored body error", statuses[i].verified);
        size_t before = setter_calls; br_results out = run(&s, &s.ctx, true, live_key);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && setter_calls == before + 1);
        check_result(&out.items[0], live_key, statuses[i].verified, statuses[i].cause); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Lob result"}, {7, "cannot allocate Lob verification cause"},
        {-1, NULL}, {1, live_key}, {1, "invalid API response"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        script s; setup(&s, 422, NULL, NULL, false); s.http.send_rc = failures[i].rc; s.http.send_error = failures[i].cause;
        br_results out = run(&s, &s.ctx, true, live_key);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], live_key, false, failures[i].cause ? failures[i].cause : "HTTP transport failed");
        br_results_clear(&out);
    }
    script s; setup(&s, 422, NULL, NULL, false);
    br_results out = run(&s, NULL, true, live_key);
    CHECK(out.len == 1 && !s.http.calls && !s.http.releases);
    check_result(&out.items[0], live_key, false, "net/http: nil Context"); br_results_clear(&out);
}

static void typed_responses(void)
{
    const struct { const char *body, *read_error; bool verified; const char *cause; } cases[] = {
        {"{\"error\":{\"code\":\"billing_address_required\"}}", NULL, true, NULL},
        {"{\"error\":{\"code\":\"feature_limit_reached\"}} trailing {", "late read failure", true, NULL},
        {"{\"error\":{\"code\":\"invalid_api_key\"}}", NULL, false, NULL},
        {"{\"ERROR\":{\"CODE\":\"feature_limit_reached\"}}", NULL, true, NULL},
        {"{\"error\":{\"code\":\"invalid_api_key\",\"code\":\"billing_address_required\",\"code\":null},\"error\":null,\"error\":{}}", NULL, true, NULL},
        {"{\"error\":{\"code\":\"billing_address_required\"},\"error\":{\"code\":\"invalid_api_key\"}}", NULL, false, NULL},
        {"{\"error\":{\"code\":\"feature_limit_reached\"},\"error\":{\"unknown\":1e99999999999999999999},\"huge\":9999999999999999999999999999999999999999}", NULL, true, NULL},
        {"{\"error\":{\"code\":\"x\\u0000y\",\"code\":\"billing_address_required\"}}", NULL, true, NULL},
        {"{}", "late read failure", false, "unexpected error code: <> in the API response body"},
        {"null", NULL, false, "unexpected error code: <> in the API response body"},
        {"{\"error\":null}", NULL, false, "unexpected error code: <> in the API response body"},
        {"{\"error\":{\"code\":null}}", NULL, false, "unexpected error code: <> in the API response body"},
        {"{\"errors\":{\"code\":\"feature_limit_reached\"}}", NULL, false, "unexpected error code: <> in the API response body"},
        {"{\"error\":{\"codes\":\"feature_limit_reached\"}}", NULL, false, "unexpected error code: <> in the API response body"},
        {"{\"error\":{\"code\":\"Billing_address_required\"}}", NULL, false, "unexpected error code: <Billing_address_required> in the API response body"},
        {"{\"error\":{\"code\":\" feature_limit_reached \"}}", NULL, false, "unexpected error code: < feature_limit_reached > in the API response body"},
        {"{\"error\":{\"code\":\"d\u00e9j\u00e0\U0001f4a1\\n\"}}", NULL, false, "unexpected error code: <d\u00e9j\u00e0\U0001f4a1\n> in the API response body"},
        {"{\"error\":{\"code\":\"\xff\\n\xef\xbf\xbd\"}}", NULL, false, "unexpected error code: <\xef\xbf\xbd\n\xef\xbf\xbd> in the API response body"},
        {"{\"error\":{\"code\":\"\\ud800\"}}", NULL, false, "unexpected error code: <\xef\xbf\xbd> in the API response body"},
        {"{\"error\":{\"code\":\"\\u0001\"}}", NULL, false, "unexpected error code: <\x01> in the API response body"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        script s; setup(&s, 403, cases[i].body, cases[i].read_error, cases[i].verified);
        br_results out = run(&s, &s.ctx, true, live_key);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], live_key, cases[i].verified, cases[i].cause); br_results_clear(&out);
    }
    const char *invalid[] = {
        "", " ", "{", "{\"error\":{\"code\":\"feature_limit_reached\"}", "{\"error\":{},}",
        "[]", "true", "0", "\"text\"", "{\"error\":[]}", "{\"error\":false}", "{\"error\":\"text\"}",
        "{\"error\":{\"code\":[]}}", "{\"error\":{\"code\":{}}}", "{\"error\":{\"code\":false}}",
        "{\"error\":{\"code\":7,\"code\":\"billing_address_required\"}}",
        "{\"error\":false,\"error\":{\"code\":\"billing_address_required\"}}",
        "{\"error\":{\"code\":\"feature_limit_reached\",\"code\":0}}",
        "{\"error\":{\"code\":7,\"code\":\"x\\u0000y\"}}",
        "{\"error\":{\"code\":\"x\\u0000y\",\"code\":false}}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        script s; setup(&s, 403, invalid[i], i < 4 ? "read failure" : NULL, false);
        br_results out = run(&s, &s.ctx, true, live_key);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], live_key, false, "invalid API response"); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void preparation_failures(void)
{
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        script s; setup(&s, 422, NULL, NULL, false);
        if (i == 0) s.ctx.transport = NULL;
        if (i == 1) s.transport.send = NULL;
        if (i == 2) s.ctx.cancelled = cancelled;
        if (i == 3) s.ctx.deadline_monotonic_ms = 1;
        if (i == 4) s.ctx.user_agent = "bad\r\nagent";
        if (i == 5) s.ctx.cancelled = arm_headers;
        if (i == 6) { s.ctx.cancelled = arm_agent; s.ctx.user_agent = NULL; }
        br_results out = run(&s, &s.ctx, true, live_key);
        CHECK(out.len == 1 && !s.http.calls && s.http.releases == (i ? 1u : 0u) && !fail_after && !fail_agent);
        check_result(&out.items[0], live_key, false, causes[i]); br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->verified && prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_boundary(void)
{
    /* Two distinct keys suffice; map iteration order is never asserted. */
    char input[100]; snprintf(input, sizeof(input), "%s %s", live_key, test_key);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    const char *expected_errors[] = {
        "out of memory iterating regex", "out of memory copying detector capture", "cannot create Lob result",
        "cannot create Lob result", "cannot insert Lob environment", "out of memory constructing Basic authentication",
        "cannot store Lob verification error", "cannot store Lob verification error",
    };
    for (size_t failure = 0; failure < sizeof(expected_errors) / sizeof(*expected_errors); ++failure) {
        script s; setup(&s, failure == 7 ? 500 : 422, NULL, NULL, failure != 7);
        if (failure == 0) { fail_size = 3 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 41; fail_after = 2; }
        if (failure == 2) { fail_size = 40; fail_after = 2; }
        if (failure == 3) fail_key_after = 2;
        if (failure == 4) fail_env_after = 2;
        if (failure == 5) { fail_size = 63; fail_after = 2; } /* Basic helper returns +1. */
        if (failure == 6) fail_setter_after = 2; /* Mandatory NULL-cause +1 must be fatal. */
        if (failure == 7) { fail_strdup_text = "unexpected status code: 500"; fail_strdup_after = 4; }
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !strcmp(error, expected_errors[failure]));
        CHECK(!fail_after && !fail_key_after && !fail_env_after && !fail_setter_after && !fail_strdup_after);
        CHECK(s.http.calls == (failure < 2 ? 0u : failure < 6 ? 1u : 2u) && s.http.releases == s.http.calls && !s.borrowed_auth);
        check_prior(&out, &prior); free(error); fail_strdup_text = NULL;
    }
    /* The ordinary type mismatch must not bypass the later +1 projector. */
    script s; setup(&s, 403, "{\"error\":{\"code\":7,\"code\":\"later\"}}", NULL, false);
    size_t projections_before = projection_calls; fail_projection_after = 1;
    char *error = NULL;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !fail_projection_after);
    CHECK(!strcmp(error, "synthetic positive Lob string projection failure") && projection_calls == projections_before + 1);
    CHECK(s.http.calls == 1 && s.http.releases == 1 && setter_calls == s.setters_before);
    check_prior(&out, &prior); free(error); error = NULL;
    setup(&s, 403, "{\"error\":{\"code\":\"unknown-long-diagnostic-material\"}}", NULL, false);
    fail_cause_after_projection = true;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !fail_cause_after_projection && !fail_after);
    CHECK(!strcmp(error, "cannot allocate Lob verification cause") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error); error = NULL;
    const char *nul_codes[] = {"{\"error\":{\"code\":\"x\\u0000y\"}}", "{\"error\":{\"code\":\"billing_address_required\\u0000\"}}"};
    for (size_t i = 0; i < sizeof(nul_codes) / sizeof(*nul_codes); ++i) {
        setup(&s, 403, nul_codes[i], NULL, false);
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
        CHECK(!strcmp(error, "unsupported: Lob error code contains NUL in verification diagnostic"));
        CHECK(s.http.calls == 1 && s.http.releases == 1 && setter_calls == s.setters_before);
        check_prior(&out, &prior); free(error); error = NULL;
    }
    /* Finding/metadata failures win before nil handling and NoV publication. */
    for (size_t mode = 0; mode < 3; ++mode) {
        setup(&s, 422, NULL, NULL, false);
        if (mode == 0) fail_env_after = 1;
        if (mode == 1) { fail_strdup_text = "net/http: nil Context"; fail_strdup_after = 1; }
        if (mode == 2) { fail_size = 40; fail_after = 2; }
        CHECK(invoke(&s, NULL, mode != 2, data, &out, &error) != 0 && error);
        CHECK(!fail_env_after && !fail_strdup_after && !fail_after && !s.http.calls && !s.http.releases);
        check_prior(&out, &prior); free(error); error = NULL; fail_strdup_text = NULL;
    }
    setup(&s, 422, NULL, NULL, true);
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Lob result") && s.http.calls == 1 && s.http.releases == 1 && setter_calls == s.setters_before + 1);
    check_prior(&out, &prior); free(error);
    fail_env_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_env_after);
    check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_extraction();
    ordinary_verification();
    typed_responses();
    preparation_failures();
    owned_failures_and_boundary();
    CHECK(!active && !fail_after && !fail_key_after && !fail_env_after && !fail_setter_after && !fail_projection_after && !fail_strdup_after && !fail_agent && !fail_cause_after_projection);
    return test_finish("Lob");
}
