/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[46], other[46];
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
    test_key_result(r, 184, expected, "key");
    CHECK(r->verified == verified && !r->verification_error);
}
static br_results scan_key(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *value)
{
    char input[48]; size_t n = strlen(value); CHECK(n <= 46);
    memcpy(input, value, n); input[n++] = ' ';
    return test_scan(d, ctx, verify, input, n);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gocardless_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_gocardless_init(&d, &error) == 0 && d && !error);
    CHECK(br_gocardless_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 184 && d->version == 0 && !strcmp(d->name, "GoCardless") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GoCardless is an online payments service that makes collecting payments by direct debit easy for everyone. GoCardless API keys can be used to access and manage payment transactions."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gocardless"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extraction(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    char input[256], expected[47], changed[47];
    const char delimiters[] = " \"'\r\n";
    for (size_t i = 0; i < sizeof(delimiters) - 1; ++i) {
        memcpy(input, key, 45); input[45] = delimiters[i];
        memcpy(expected, key, 46);
        if (delimiters[i] == '\"' || delimiters[i] == '\'') { expected[45] = delimiters[i]; expected[46] = '\0'; }
        br_results r = test_scan(d, &ctx, false, input, 46); CHECK(r.len == 1); result_check(&r.items[0], expected, false); br_results_clear(&r);
    }
    const char *formats[] = {"%s ", "gocardless %s ", "%s gocardless", "GOCARDLESS..................................................%s ", "-%s x", "\xc3\xa9%s \t", "\"%s\""};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), formats[i], key);
        br_results r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 1);
        strcpy(expected, key); if (i == 6) strcat(expected, "\"");
        result_check(&r.items[0], expected, false); br_results_clear(&r);
    }
    const char *bad[] = {"%s", "%s\t", "%s\v", "%s\f", "%sX ", "%s- ", "x%s ", "_%s ", "%s,", "%s\xc2\xa0"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        int n = snprintf(input, sizeof(input), bad[i], key); br_results r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    strcpy(changed, key); changed[0] = 'L'; br_results r = scan_key(d, &ctx, false, changed); CHECK(!r.len); br_results_clear(&r);
    strcpy(changed, key); changed[44] = '\0'; r = scan_key(d, &ctx, false, changed); CHECK(!r.len); br_results_clear(&r);
    strcpy(changed, key); changed[44] = '_'; r = scan_key(d, &ctx, false, changed); CHECK(r.len == 1); result_check(&r.items[0], changed, false); br_results_clear(&r);
    changed[44] = '-'; r = scan_key(d, &ctx, false, changed); CHECK(r.len == 1); result_check(&r.items[0], changed, false); br_results_clear(&r);
    memcpy(changed, "live_", 5); memset(changed + 5, 'a', 40); changed[45] = '\0'; r = scan_key(d, &ctx, false, changed); CHECK(r.len == 1); result_check(&r.items[0], changed, false); br_results_clear(&r);
    /* The delimiter is consumed, but the next search retains source boundary context. */
    int n = snprintf(input, sizeof(input), "%s %s\"%s ", key, other, key);
    r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 3);
    result_check(&r.items[0], key, false); strcpy(expected, other); strcat(expected, "\""); result_check(&r.items[1], expected, false); result_check(&r.items[2], key, false); br_results_clear(&r);
    n = snprintf(input, sizeof(input), "%s x%s %s ", key, other, key); r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 2); result_check(&r.items[0], key, false); result_check(&r.items[1], key, false); br_results_clear(&r);
    /* An earlier invalid start must not suppress a later valid start. */
    n = snprintf(input, sizeof(input), "live_short-%s ", key); r = test_scan(d, &ctx, false, input, (size_t)n); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    memcpy(input, key, 45); input[45] = ' '; input[46] = '\0'; memcpy(input + 47, other, 45); input[92] = '\n';
    r = test_scan(d, &ctx, false, input, 93); CHECK(r.len == 2); result_check(&r.items[0], key, false); result_check(&r.items[1], other, false); br_results_clear(&r);
    CHECK(!http.calls && !http.releases);
    r = scan_key(d, NULL, false, key); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    r = scan_key(d, NULL, true, key); CHECK(!r.len && !r.items && !r.cap); br_results_clear(&r);
}

typedef struct {
    const br_scan_ctx *ctx;
    const char *key, *borrowed_auth;
    int status, send_rc;
    const char *send_error;
    bool empty, default_agent, mixed;
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; CHECK(ctx == s->ctx && http->calls == http->releases + 1);
    CHECK(!strcmp(request->url, "https://api.gocardless.com/customers/"));
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 184);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, s->key));
    CHECK(!strcmp(request->headers[2].name, "Gocardless-Version") && !strcmp(request->headers[2].value, "2015-07-06"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, s->default_agent ? "TruffleHog" : "TruffleHog gocardless-offline"));
    /* Only the module-owned auth value is borrowed beyond send, not effective headers/UA. */
    s->borrowed_auth = request->headers[1].value;
    static const unsigned char body[] = "\0\xff not JSON";
    http->response = s->empty ? (br_http_response){0} : (br_http_response){.status = s->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored body read failure"};
    http->send_rc = s->mixed && http->calls % 2 == 0 ? -1 : s->send_rc;
    http->send_error = s->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_auth && !strncmp(s->borrowed_auth, "Bearer ", 7) && !strcmp(s->borrowed_auth + 7, s->key));
    s->borrowed_auth = NULL; test_http_release(user, response);
}
static void verification(const br_detector *d)
{
    script s = {.key = key}; test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "gocardless-offline"}; s.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 206, 226, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i]; br_results r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, s.status >= 200 && s.status < 300); br_results_clear(&r);
    }
    char quoted[47]; strcpy(quoted, key); strcat(quoted, "'"); s.key = quoted; s.status = 200;
    br_results r = scan_key(d, &ctx, true, quoted); CHECK(r.len == 1); result_check(&r.items[0], quoted, true); br_results_clear(&r); s.key = key;
    ctx.user_agent = NULL; s.default_agent = true; r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, true); br_results_clear(&r); ctx.user_agent = "gocardless-offline"; s.default_agent = false;
    const char *errors[] = {"context canceled", "context deadline exceeded", "out of memory constructing HTTP headers", "cannot create GoCardless result", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        s.send_rc = -9; s.send_error = errors[i]; s.empty = i % 2 != 0;
        r = scan_key(d, &ctx, true, key); CHECK(r.len == 1); result_check(&r.items[0], key, false); br_results_clear(&r);
    }
    s.send_rc = 0; s.send_error = NULL; s.empty = false; s.mixed = true;
    char input[150]; int n = snprintf(input, sizeof(input), "%s %s %s ", key, key, key); size_t before = http.calls;
    r = test_scan(d, &ctx, true, input, (size_t)n); CHECK(r.len == 3 && http.calls == before + 3);
    for (size_t i = 0; i < 3; ++i) result_check(&r.items[i], key, (before + i + 1) % 2 != 0);
    br_results_clear(&r); CHECK(http.calls == http.releases && !s.borrowed_auth);
}
static bool cancelled(void *unused) { (void)unused; return true; }
static bool fail_headers(void *unused) { (void)unused; fail_size = 4 * sizeof(br_header); fail_after = 1; return false; }
static bool fail_agent(void *unused) { (void)unused; fail_size = sizeof("TruffleHog ") + strlen("gocardless-offline"); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    for (int mode = 0; mode < 6; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : mode == 4 ? fail_agent : NULL, .deadline_monotonic_ms = mode == 3 ? 1 : 0, .user_agent = mode == 5 ? "invalid\nagent" : "gocardless-offline"};
        size_t before = allocation_failures; br_results r = scan_key(d, &ctx, true, key);
        CHECK(r.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 || mode == 4 ? 1u : 0u));
        result_check(&r.items[0], key, false); br_results_clear(&r);
    }
    char input[100]; int n = snprintf(input, sizeof(input), "%s %s ", key, key); br_slice data = {(const unsigned char *)input, (size_t)n};
    for (int mode = 0; mode < 3; ++mode) {
        br_results r = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verification_error = strdup("caller-owned"); prior.verified = true; CHECK(prior.verification_error && br_results_push(&r, &prior) == 0);
        unsigned char *raw = r.items[0].raw.data; br_json *parts = r.items[0].secret_parts; char *cause = r.items[0].verification_error;
        test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        char *error = NULL; fail_parts = 2;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &r, &error) != 0 && error && !strcmp(error, "cannot create GoCardless result") && !fail_parts);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.calls == http.releases); free(error); error = NULL;
        CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause && r.items[0].verified && !strcmp(cause, "caller-owned"));
        const size_t sizes[] = {2 * sizeof(br_span), 8 * sizeof(char *), 47, 45};
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
            fail_size = sizes[i]; fail_after = i >= 2 ? 2 : 1;
            size_t before = allocation_failures;
            CHECK(d->scan(d, NULL, true, data, &r, &error) != 0 && error && !fail_after && allocation_failures == before + 1); free(error); error = NULL;
            CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause);
        }
        size_t cap = r.cap; r.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &r, &error) != 0 && error && !strcmp(error, "cannot append GoCardless result")); r.cap = cap; free(error);
        CHECK(r.len == 1 && r.items[0].raw.data == raw && r.items[0].secret_parts == parts && r.items[0].verification_error == cause && !memcmp(raw, "prior", 5)); br_results_clear(&r);
    }
}
int main(void)
{
    memcpy(key, "live_", 5); test_secret(key + 5, 40, 0); key[9] = 'Z'; key[19] = '_'; key[29] = '-';
    memcpy(other, "live_", 5); test_secret(other + 5, 40, 13);
    const br_detector *d = descriptor(); extraction(d); verification(d); resources(d); return test_finish("GoCardless");
}
