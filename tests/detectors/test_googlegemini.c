/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error googlegemini_real_setter
#define br_results_push googlegemini_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

static size_t fail_size, fail_after, fail_part, fail_meta, fail_setter, fail_push, setter_calls;
static char key[40], other[40];
void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "key") && fail_part && --fail_part == 0) return 1;
    if (!strcmp(name, "active_google_key") && fail_meta && --fail_meta == 0) return 1;
    return json_object_object_add_ex(o, name, v, 0);
}
int br_result_set_verification_error(br_result *r, const char *c, const br_slice *s, size_t n)
{
    ++setter_calls;
    CHECK(!s && !n && r->redacted && r->raw.len == 39);
    if (fail_setter && --fail_setter == 0) return 1;
    return googlegemini_real_setter(r, c, s, n);
}
int br_results_push(br_results *r, br_result *v)
{
    if (fail_push && --fail_push == 0) return 1;
    return googlegemini_real_push(r, v);
}
static void result(const br_result *r, const char *value, bool verified, bool active, const char *cause)
{
    br_result plain = *r; plain.redacted = NULL; plain.extra_data = NULL;
    test_key_result(&plain, 1041, value, "key");
    CHECK(r->raw.len == 39 && r->verified == verified);
    CHECK(r->redacted && strlen(r->redacted) == 11 && !memcmp(r->redacted, value, 8) && !strcmp(r->redacted + 8, "..."));
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    if (active) {
        br_json *v = NULL;
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
        CHECK(json_object_object_get_ex(r->extra_data, "active_google_key", &v));
        CHECK(json_object_is_type(v, json_type_string) && !strcmp(json_object_get_string(v), "true"));
    } else CHECK(!r->extra_data);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_googlegemini_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_googlegemini_init(&d, NULL) == 0 && d);
    CHECK(br_googlegemini_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1041 && !d->version && !strcmp(d->name, "GoogleGeminiAPIKey") && !*d->custom_name);
    CHECK(!strcmp(d->description, "Google Gemini API provides access to Google's latest generative AI models for building applications that understand and generate text, images, audio, and code with high performance and low latency."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "aizasy"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extraction(const br_detector *d)
{
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    char input[256], changed[40];
    const struct { const char *format; bool match; } cases[] = {
        {"%s", true}, {"-%s", true}, {"%sX_longertoken", true}, {"aizasy distant %s", true},
        {"x%s", false}, {"_%s", false}, {"%.38s", false}, {"%s_", true}, {"\xc3\xa9%s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, key);
        br_results out = test_scan(d, &ctx, false, input, (size_t)n);
        CHECK(out.len == (cases[i].match ? 1u : 0u));
        if (out.len) result(&out.items[0], key, false, false, NULL);
        br_results_clear(&out);
    }
    for (size_t i = 0; i < 6; ++i) {
        strcpy(changed, key); changed[i] = changed[i] >= 'a' ? (char)(changed[i] - 32) : (char)(changed[i] + 32);
        br_results out = test_scan(d, &ctx, false, changed, 39); CHECK(!out.len); br_results_clear(&out);
    }
    strcpy(changed, key); memset(changed + 6, 'A', 33); changed[39] = 0;
    br_results out = test_scan(d, &ctx, false, changed, 39); CHECK(out.len == 1); result(&out.items[0], changed, false, false, NULL); br_results_clear(&out);
    int n = snprintf(input, sizeof(input), "%s %s %s", key, other, key);
    out = test_scan(d, &ctx, false, input, (size_t)n); CHECK(out.len == 3);
    result(&out.items[0], key, false, false, NULL); result(&out.items[1], other, false, false, NULL); result(&out.items[2], key, false, false, NULL);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].redacted != out.items[2].redacted);
    br_results_clear(&out); CHECK(!http.calls && !http.releases && !setter_calls);
    out = test_scan(d, NULL, true, key, 39); CHECK(out.len == 1); result(&out.items[0], key, false, false, "net/http: nil Context"); br_results_clear(&out);
}
static const char *borrowed_key;
static void inspect(test_http *h, const br_scan_ctx *ctx, const br_http_request *r)
{
    CHECK(ctx && h->calls == h->releases + 1 && !borrowed_key);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://generativelanguage.googleapis.com/v1/models"));
    CHECK(r->detector_type == 1041 && r->profile == BR_HTTP_SANE && r->timeout_ms == 5000);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len && r->nheaders == 3);
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!strcmp(r->headers[1].name, "X-Goog-Api-Key") && !strcmp(r->headers[1].value, key));
    CHECK(!strcmp(r->headers[2].name, "User-Agent") && !strcmp(r->headers[2].value, ctx->user_agent ? "TruffleHog gemini-offline" : "TruffleHog"));
    borrowed_key = r->headers[1].value;
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_key && !strcmp(borrowed_key, key)); borrowed_key = NULL;
    test_http_release(user, response);
}
static void verification(const br_detector *d)
{
    test_http http = {.inspect = inspect}; br_transport t = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &t, .user_agent = "gemini-offline"};
    const int statuses[] = {200, 403, 400, 201, 401, 429, 500, 0};
    const unsigned char ignored[] = {0, 255, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        int s = statuses[i]; char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", s);
        http.response = (br_http_response){.status = s, .body = {ignored, sizeof(ignored)}, .body_error = "ignored read failure"};
        br_results out = test_scan(d, &ctx, true, key, 39); CHECK(out.len == 1);
        result(&out.items[0], key, s == 200, s == 200 || s == 403, s == 200 || s == 403 || s == 400 ? NULL : cause); br_results_clear(&out);
    }
    const char *causes[] = {key, "error making request: arbitrary diagnostic", "out of memory constructing HTTP headers", "context canceled", "context deadline exceeded", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        http.send_rc = i % 2 ? 1 : -7; http.send_error = causes[i]; http.response = (br_http_response){0};
        br_results out = test_scan(d, &ctx, true, key, 39); CHECK(out.len == 1); result(&out.items[0], key, false, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    http.send_rc = 0; http.send_error = NULL; http.response.status = 200; ctx.user_agent = NULL;
    char input[128]; int n = snprintf(input, sizeof(input), "%s %s %s", key, key, key); size_t before = http.calls;
    br_results out = test_scan(d, &ctx, true, input, (size_t)n); CHECK(out.len == 3 && http.calls == before + 3);
    for (size_t i = 0; i < out.len; ++i) result(&out.items[i], key, true, true, NULL);
    br_results_clear(&out); CHECK(http.calls == http.releases && !borrowed_key);
}
static bool cancel(void *unused) { (void)unused; return true; }
static bool fail_headers(void *unused) { (void)unused; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    test_http http = {.response = {.status = 200}}; br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t};
    br_scan_ctx setup[] = {{.transport = &t, .cancelled = cancel}, {.transport = &t, .cancelled = fail_headers}, {.transport = &t, .user_agent = "bad\nagent"}};
    for (size_t i = 0; i < sizeof(setup) / sizeof(setup[0]); ++i) {
        size_t before = http.releases; br_results out = test_scan(d, &setup[i], true, key, 39);
        CHECK(out.len == 1 && !out.items[0].verified && out.items[0].verification_error && http.releases == before + 1 && !http.calls && !fail_after);
        br_results_clear(&out);
    }
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); prior.verified = true;
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char input[90]; int n = snprintf(input, sizeof(input), "%s %s", key, key); br_slice data = {(const unsigned char *)input, (size_t)n};
    for (int mode = 0; mode < 10; ++mode) {
        char *error = NULL; http.calls = http.releases = 0;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (mode == 1) { fail_size = 40; fail_after = 2; }
        if (mode == 2) { fail_size = 39; fail_after = 2; }
        if (mode == 3) fail_part = 2;
        if (mode == 4) { fail_size = 12; fail_after = 2; }
        if (mode == 5) fail_meta = 2;
        if (mode == 6 || mode == 7) fail_setter = 2;
        if (mode == 8) fail_push = 2;
        if (mode == 9) { fail_size = sizeof("net/http: nil Context"); fail_after = 1; }
        CHECK(d->scan(d, mode == 7 || mode == 9 ? NULL : &ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part && !fail_meta && !fail_setter && !fail_push);
        CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
        CHECK(http.calls == http.releases); free(error);
    }
    br_results_clear(&out);
}
int main(void)
{
    memcpy(key, "AIzaSy", 6); test_secret(key + 6, 33, 0); key[15] = 'Z'; key[23] = '_'; key[38] = '-';
    memcpy(other, "AIzaSy", 6); test_secret(other + 6, 33, 11);
    const br_detector *d = descriptor(); extraction(d); verification(d); resources(d);
    return test_finish("GoogleGeminiAPIKey");
}
