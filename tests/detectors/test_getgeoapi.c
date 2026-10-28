/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[41], other[41];
static size_t fail_size, fail_after, fail_parts, allocation_failures;
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_parts && --fail_parts == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void result_check(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 383, expected, "key");
    CHECK(r->verified == verified && !r->verification_error);
}
static br_results scan_key(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *value)
{
    char input[128]; int n = snprintf(input, sizeof(input), "getgeoapi %s", value);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    return test_scan(d, ctx, verify, input, (size_t)n);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_getgeoapi_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_getgeoapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_getgeoapi_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 383 && d->version == 0 && !strcmp(d->name, "GetGeoAPI") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GetGeoAPI provides geolocation and currency conversion services. The API keys can be used to access these services and retrieve data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "getgeoapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extraction(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    char input[300], value[48];
    const char *formats[] = {"getgeoapi %s", "GETGEOAPI\r\n\t%s", "preGeTgEoApIsuffix: '%s'", "getgeoapi \xc2\xa0%s\xc2\xa0"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), formats[i], key);
        br_results r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    }
    /* Lower-alphanumeric, deliberately including g/z: not a hex pattern. */
    CHECK(strchr(key, 'g') && strchr(key, 'z'));
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "getgeoapi", 9); memset(input + 9, ' ', gap); memcpy(input + 9 + gap, key, 40);
        br_results r = test_scan(d, &ctx, false, input, 49 + gap); CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    const char *bad_formats[] = {"%s", "getgeoapi _%s", "getgeoapi %s_", "getgeoapi x%s", "getgeoapi %sx"};
    for (size_t i = 0; i < sizeof(bad_formats) / sizeof(bad_formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), bad_formats[i], key); br_results r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    memcpy(value, key, 41); value[15] = 'G'; br_results r = scan_key(d, &ctx, false, value); CHECK(!r.len); br_results_clear(&r);
    memcpy(value, key, 41); value[39] = '\0'; r = scan_key(d, &ctx, false, value); CHECK(!r.len); br_results_clear(&r);
    int n = snprintf(input, sizeof(input), "getgeoapi %s %s;getgeoapi %s;getgeoapi %s", key, other, other, key);
    r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 3);
    result_check(&r.items[0], key, false); result_check(&r.items[1], other, false); result_check(&r.items[2], key, false); br_results_clear(&r);
    CHECK(!http.calls && !http.releases);
    r = scan_key(d, NULL, false, key); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    r = scan_key(d, NULL, true, key); CHECK(!r.len && !r.items && !r.cap); br_results_clear(&r);
}

typedef struct {
    const br_scan_ctx *ctx;
    const char *key, *borrowed_url, *borrowed_header_name, *borrowed_header_value;
    int status, send_rc;
    const char *send_error;
    bool empty_body, default_agent;
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; CHECK(ctx == s->ctx && http->calls == http->releases + 1);
    char expected[100]; int n = snprintf(expected, sizeof(expected), "https://api.getgeoapi.com/v2/currency/list?api_key=%s", s->key);
    CHECK(n > 0 && (size_t)n < sizeof(expected) && !strcmp(request->url, expected));
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 383);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->default_agent ? "TruffleHog" : "TruffleHog getgeoapi-offline"));
    /* Retain only provider values, never the synthesized request/headers/UA. */
    s->borrowed_url = request->url; s->borrowed_header_name = request->headers[0].name; s->borrowed_header_value = request->headers[0].value;
    static const unsigned char body[] = "\0\xff not JSON / rejected";
    http->response = (br_http_response){.status = s->status, .body = s->empty_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1}, .body_error = "ignored read failure"};
    http->send_rc = s->send_rc; http->send_error = s->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_url && strstr(s->borrowed_url, s->key) && strlen(s->borrowed_url) == sizeof("https://api.getgeoapi.com/v2/currency/list?api_key=") - 1 + 40);
    CHECK(!strcmp(s->borrowed_header_name, "Content-Type") && !strcmp(s->borrowed_header_value, "application/json"));
    s->borrowed_url = s->borrowed_header_name = s->borrowed_header_value = NULL;
    test_http_release(user, response);
}
static void verification(const br_detector *d)
{
    script s = {.key = key}; test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "getgeoapi-offline"}; s.ctx = &ctx;
    for (int status = 99; status <= 600; ++status) {
        s.status = status; s.empty_body = status % 2 != 0;
        br_results r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, status >= 200 && status < 300); br_results_clear(&r);
    }
    s.default_agent = true; ctx.user_agent = NULL; s.status = 200;
    br_results r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, true); br_results_clear(&r);
    const char *errors[] = {"context canceled", "context deadline exceeded", "out of memory constructing HTTP headers", "cannot create GetGeoAPI result", key};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        s.send_rc = -9; s.send_error = errors[i]; r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    }
    s.send_error = NULL; r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    s.send_rc = 0; char input[220]; int n = snprintf(input, sizeof(input), "getgeoapi %s;getgeoapi %s", key, key); size_t before = http.calls;
    r = test_scan(d, &ctx, true, input, (size_t)n); CHECK(r.len == 2 && http.calls == before + 2); result_check(&r.items[0], key, true); result_check(&r.items[1], key, true); br_results_clear(&r);
    CHECK(http.calls == http.releases && !s.borrowed_url);
}
static bool cancelled(void *unused) { (void)unused; return true; }
static bool fail_headers(void *unused) { (void)unused; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL, .deadline_monotonic_ms = mode == 3 ? 1 : 0};
        size_t before = allocation_failures; br_results r = scan_key(d, &ctx, true, key);
        CHECK(r.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        result_check(&r.items[0], key, false); br_results_clear(&r);
    }
    char input[130]; int n = snprintf(input, sizeof(input), "getgeoapi %s;getgeoapi %s", key, other); br_slice data = {(const unsigned char *)input, (size_t)n};
    for (int mode = 0; mode < 3; ++mode) {
        br_results r = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verification_error = strdup("caller-owned"); prior.verified = true; CHECK(prior.verification_error && br_results_push(&r, &prior) == 0);
        unsigned char *raw = r.items[0].raw.data; br_json *parts = r.items[0].secret_parts; char *cause = r.items[0].verification_error;
        script s = {.key = key, .status = 200}; test_http http = {.inspect = inspect, .user = &s}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "getgeoapi-offline"}; s.ctx = &ctx;
        char *error = NULL; fail_parts = 2;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &r, &error) != 0 && error && !strcmp(error, "cannot create GetGeoAPI result") && !fail_parts);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.calls == http.releases); free(error); error = NULL;
        CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause && r.items[0].verified && !strcmp(cause, "caller-owned"));
        fail_size = 2 * sizeof(br_span); fail_after = 1;
        CHECK(d->scan(d, NULL, true, data, &r, &error) != 0 && error && !fail_after); free(error); error = NULL;
        CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause);
        size_t cap = r.cap; r.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &r, &error) != 0 && error && !strcmp(error, "cannot append GetGeoAPI result")); r.cap = cap; free(error);
        CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause && !memcmp(raw, "prior", 5)); br_results_clear(&r);
    }
}
int main(void)
{
    test_secret(key, 40, 0); key[0] = 'g'; key[39] = 'z'; test_secret(other, 40, 13);
    const br_detector *d = descriptor(); extraction(d); verification(d); resources(d); return test_finish("GetGeoAPI");
}
