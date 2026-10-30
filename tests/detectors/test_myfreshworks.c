/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_myfreshworks_init(const br_detector **out, char **error);

static const char key[] = "abcdefg_hijklmnopqrSTU";
static const char other_key[] = "zzzzzzzzzzzzzzzzzzzzzz";
static const char hyphen_key[] = "ab-cd_efghijklmnopqrST";
static const char id[] = "acme";
static const char other_id[] = "ab-cd";
static const char long_id[] = "abcdefghijklmnopqrst";
static const char suffix[] = ".myfreshworks.com/crm/sales/api/sales_accounts/filters";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size, setter_fail_size;
static bool arm_http_headers, arm_setter;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key") && arm_http_headers) {
        arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static size_t add_gap(char *out, size_t at)
{
    memset(out + at, ' ', 41);
    return at + 41;
}

static void finding(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 216, expected, "key");
    CHECK(result->verified == verified);
    CHECK(result->secret_parts && !json_object_object_get_ex(result->secret_parts, "id", NULL));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen("freshworks") == 10 && strlen("myfreshworks") == 12);
    CHECK(strlen(key) == 22 && strlen(other_key) == 22 && strlen(hyphen_key) == 22);
    CHECK(strlen(id) == 4 && strlen(other_id) == 5 && strlen(long_id) == 20 && strlen(suffix) == 54);
    CHECK(strchr(key, '_') && strchr(hyphen_key, '-') && strchr(other_id, '-'));
    CHECK(br_myfreshworks_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_myfreshworks_init(&d, &error) == 0 && d && !error);
    CHECK(br_myfreshworks_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 216 && d->version == 0 && !strcmp(d->name, "Myfreshworks"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Freshworks is a customer engagement platform offering various services like CRM, IT service management, and more. Freshworks API keys can be used to access and manage these services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "freshworks"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static br_results scan_text(const br_detector *d, bool verify, const void *data, size_t len)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, verify, data, len);
    CHECK(!http.calls && !http.releases);
    return out;
}

static void extraction(const br_detector *d)
{
    char input[320];
    br_results out = scan_text(d, false, key, strlen(key)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %s", key);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %s", id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s", key, id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %s %s", key, id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "FRESHWORKS %s %s", other_key, other_id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], other_key, false, NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "myfreshworks %s %s", key, long_id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    size_t at = snprintf(input, sizeof(input), "freshworks %s xy", key);
    at = add_gap(input, at);
    snprintf(input + at, sizeof(input) - at, "freshworks %s", long_id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 2);
    finding(&out.items[0], key, false, NULL); finding(&out.items[1], key, false, NULL);
    br_results_clear(&out);
    /* One keyword yields one ID match. The hyphen ends that capture at ab. */
    snprintf(input, sizeof(input), "freshworks %s", hyphen_key);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], hyphen_key, false, NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %.21s\nfreshworks %s", key, id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %sx\nfreshworks %s", key, id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %s-\nfreshworks %s", key, id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %s q", key);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "freshworks %sx %s", long_id, key);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    char gap[160];
    memset(gap, ' ', sizeof(gap));
    memcpy(gap, "freshworks", 10); memcpy(gap + 50, key, 22);
    memcpy(gap + 80, "freshworks", 10); memcpy(gap + 130, id, 4);
    out = scan_text(d, false, gap, 134); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    memset(gap, ' ', sizeof(gap));
    memcpy(gap, "freshworks", 10); memcpy(gap + 51, key, 22);
    memcpy(gap + 80, "freshworks ", 11); memcpy(gap + 91, id, 4);
    out = scan_text(d, false, gap, 95); CHECK(out.len == 0); br_results_clear(&out);
    char far[1400];
    memset(far, ' ', sizeof(far));
    memcpy(far, "freshworks ", 11); memcpy(far + 11, key, 22);
    memcpy(far + 1200, "freshworks ", 11); memcpy(far + 1211, id, 4);
    out = scan_text(d, false, far, 1215); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    at = snprintf(input, sizeof(input), "freshworks %s %s", key, id);
    at = add_gap(input, at);
    snprintf(input + at, sizeof(input) - at, "freshworks %s %s", other_key, other_id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 4);
    finding(&out.items[0], key, false, NULL); finding(&out.items[1], key, false, NULL);
    finding(&out.items[2], other_key, false, NULL); finding(&out.items[3], other_key, false, NULL);
    br_results_clear(&out);
    at = snprintf(input, sizeof(input), "freshworks %s", key);
    at = add_gap(input, at);
    at += snprintf(input + at, sizeof(input) - at, "freshworks %s", key);
    at = add_gap(input, at);
    snprintf(input + at, sizeof(input) - at, "freshworks %s", id);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 2);
    finding(&out.items[0], key, false, NULL); finding(&out.items[1], key, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);
}

typedef struct {
    const char *key, *id, *body, *read_error, *send_error, *expect_error;
    int status, rc; bool verified, poison_body, poison_error;
} row;
typedef struct {
    row rows[4]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char *poison_body; char *poison_error;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 4 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    char url[96], auth[48];
    snprintf(url, sizeof(url), "https://%s%s", reply->id, suffix);
    snprintf(auth, sizeof(auth), "Token token=%s", reply->key);
    CHECK(request->detector_type == 216 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && !strchr(request->url, '%'));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, auth) && !strncmp(auth, "Token token=", 12));
    CHECK(strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog myfreshworks-offline" : "TruffleHog"));
    steps->borrowed_auth = request->headers[0].value;
    http->response = (br_http_response){.status = reply->status,
        .body = reply->body ? text(reply->body) : (br_slice){0}, .body_error = reply->read_error};
    if (steps->poison_body) http->response.body = text(steps->poison_body);
    if (steps->poison_error) http->response.body_error = steps->poison_error;
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !strncmp(steps->borrowed_auth, "Token token=", 12));
    steps->borrowed_auth = NULL;
    if (steps->rows[http->calls - 1].poison_body && response->body.data && response->body.len)
        memset((void *)response->body.data, 'X', response->body.len);
    if (steps->rows[http->calls - 1].poison_error && response->body_error)
        memset((void *)response->body_error, 'X', strlen(response->body_error));
    test_http_release(user, response);
    if (arm_setter) { arm_setter = false; fail_size = setter_fail_size; fail_after = 1; }
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "myfreshworks-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth);
    return rc;
}

static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, text(input), steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_and_send_policy(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "freshworks %s %s", key, id);
    const char *valid[] = {"null", "null ", "{\"a\":1}", "[]", "\"x\"", "0", "true", "false"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(*valid); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .id = id, .status = 200, .body = valid[i], .verified = true};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true, NULL); br_results_clear(&out);
    }
    char poison[] = "null";
    script poisoned = {.count = 1, .poison_body = poison};
    poisoned.rows[0] = (row){.key = key, .id = id, .status = 200, .verified = true, .poison_body = true};
    br_results out = run(d, input, &poisoned); CHECK(out.len == 1 && !strcmp(poison, "XXXX"));
    finding(&out.items[0], key, true, NULL); br_results_clear(&out);
    const char *invalid[] = {"", "{", "null true", "{\"a\":1}x"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .id = id, .status = 200, .body = invalid[i][0] ? invalid[i] : NULL};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    }
    script read = {.count = 1};
    read.rows[0] = (row){.key = key, .id = id, .status = 200, .body = "null", .read_error = "read failed", .expect_error = "read failed"};
    out = run(d, input, &read); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "read failed"); br_results_clear(&out);
    script empty_read = {.count = 1};
    empty_read.rows[0] = (row){.key = key, .id = id, .status = 200, .body = "null", .read_error = "", .expect_error = ""};
    out = run(d, input, &empty_read); CHECK(out.len == 1);
    finding(&out.items[0], key, false, ""); br_results_clear(&out);
    char wrapped[80]; snprintf(wrapped, sizeof(wrapped), "bad %s here", key);
    char redacted[80]; snprintf(redacted, sizeof(redacted), "bad [REDACTED] here");
    char mutable_error[80]; snprintf(mutable_error, sizeof(mutable_error), "%s", wrapped);
    script redact = {.count = 1, .poison_error = mutable_error};
    redact.rows[0] = (row){.key = key, .id = id, .status = 200, .read_error = mutable_error, .expect_error = redacted, .poison_error = true};
    out = run(d, input, &redact); CHECK(out.len == 1);
    finding(&out.items[0], key, false, redacted); br_results_clear(&out);
    const int quiet[] = {401, 403};
    for (size_t i = 0; i < 2; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .id = id, .status = quiet[i], .body = "null", .read_error = "ignored"};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    }
    const int noisy[] = {0, 199, 201, 204, 300, 404, 500};
    for (size_t i = 0; i < sizeof(noisy) / sizeof(*noisy); ++i) {
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", noisy[i]);
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .id = id, .status = noisy[i], .body = "null", .read_error = "ignored", .expect_error = cause};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, cause); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "", NULL};
    const char *expect[] = {"ordinary Do error", "out of memory constructing HTTP headers", "", "HTTP transport failed"};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .id = id, .status = 200, .rc = 1, .send_error = errors[i], .expect_error = expect[i]};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, expect[i]); br_results_clear(&out);
    }
    script crossed = {.count = 4, .suffix = true};
    crossed.rows[0] = (row){.key = key, .id = id, .status = 200, .body = "null", .verified = true};
    crossed.rows[1] = (row){.key = key, .id = other_id, .status = 401, .body = "null", .read_error = "ignored"};
    crossed.rows[2] = (row){.key = other_key, .id = id, .status = 403, .body = "{", .read_error = ""};
    crossed.rows[3] = (row){.key = other_key, .id = other_id, .status = 500, .body = "null"};
    char four[240];
    size_t at = snprintf(four, sizeof(four), "freshworks %s %s", key, id);
    at = add_gap(four, at);
    snprintf(four + at, sizeof(four) - at, "freshworks %s %s", other_key, other_id);
    out = run(d, four, &crossed); CHECK(out.len == 4);
    finding(&out.items[0], key, true, NULL); finding(&out.items[1], key, false, NULL);
    finding(&out.items[2], other_key, false, NULL);
    finding(&out.items[3], other_key, false, "unexpected HTTP response status 500");
    br_results_clear(&out);
}

static void nil_and_setup(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "freshworks %s %s", key, id);
    br_results out = {0}; char *error = NULL;
    CHECK(d->scan(d, NULL, true, text(input), &out, &error) == 0 && !error && out.len == 1);
    finding(&out.items[0], key, false, "net/http: nil Context"); br_results_clear(&out);
    test_http http = {0}; br_transport blind = {&http, NULL, test_http_release};
    br_scan_ctx missing = {.transport = &blind};
    out = test_scan(d, &missing, true, input, strlen(input));
    CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "HTTP transport not installed"); br_results_clear(&out);
    http = (test_http){0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "out of memory constructing HTTP headers"); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "out of memory constructing HTTP user agent"); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "invalid HTTP user agent"); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    prior = caller.items[0]; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    caller.items[0].verification_error = prior.verification_error;
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 2);
    test_key_result(&caller.items[0], 17, "caller-owned", "key");
    CHECK(caller.items[0].verification_error == prior.verification_error);
    finding(&caller.items[1], key, false, "net/http: nil Context"); br_results_clear(&caller);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0);
    out.items[0].verification_error = strdup("caller-owned"); CHECK(out.items[0].verification_error);
    return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1);
    test_key_result(&out->items[0], 17, "caller-owned", "key");
    CHECK(out->items[0].verification_error && !strcmp(out->items[0].verification_error, "caller-owned"));
    free(error); br_results_clear(out);
}

static void own_failure_rollback(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "freshworks %s %s", key, id);
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
    fail_size = 22; fail_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    out = caller_owned(); error = NULL; fail_add_after = 1;
    rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    char sample[64]; int n = snprintf(sample, sizeof(sample), "unexpected HTTP response status %d", 500);
    CHECK(n > 0); setter_fail_size = (size_t)n + 1; arm_setter = true;
    script steps = {.count = 1};
    steps.rows[0] = (row){.key = key, .id = id, .status = 500, .body = "null", .read_error = "ignored"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!arm_setter && !fail_after && allocation_failures == before + 1);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    setter_fail_size = strlen("setter-fail") + 1; arm_setter = true;
    steps = (script){.count = 1};
    steps.rows[0] = (row){.key = key, .id = id, .status = 200, .rc = 1, .send_error = "setter-fail"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!arm_setter && !fail_after && allocation_failures == before + 1);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .id = id, .status = 200, .body = "null"};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[240];
    size_t at = snprintf(pair, sizeof(pair), "freshworks %s", key);
    at = add_gap(pair, at);
    at += snprintf(pair + at, sizeof(pair) - at, "freshworks %s", key);
    at = add_gap(pair, at);
    snprintf(pair + at, sizeof(pair) - at, "freshworks %s", id);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 22, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .id = id, .status = 200, .body = "null"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(pair), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(input), &out, NULL) == -1);
    error = NULL; CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_and_send_policy(d);
    nil_and_setup(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers && !arm_setter);
    return test_finish("Myfreshworks");
}
