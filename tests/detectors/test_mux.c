/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_mux_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other_key[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
static const char secret[] = "Ab9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xAb9+/xQ7+";
static const char known_auth[] = "Basic MDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWJjZGVmOkFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveEFiOSsveFE3Kw==";
static char other_secret[76];
static const char url[] = "https://api.mux.com/video/v1/assets";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_basic;

static void fill_secret(char *out, char marker)
{
    memset(out, marker, 75);
    out[75] = '\0';
}

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
    if (!rc && !strcmp(name, "secret")) {
        if (arm_http_headers) { arm_http_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
        if (arm_basic) { arm_basic = false; fail_size = 159; fail_after = 1; }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const char *part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void pair(const br_result *result, const char *expected_key, const char *expected_secret, bool verified)
{
    CHECK(result->detector_type == 748 && !result->detector_name && !result->redacted);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_error);
    CHECK(result->verified == verified && !result->verification_from_cache);
    CHECK(result->raw.len == 36 && !memcmp(result->raw.data, expected_key, 36));
    CHECK(result->raw_v2.len == 111 && !memcmp(result->raw_v2.data, expected_key, 36));
    CHECK(!memcmp(result->raw_v2.data + 36, expected_secret, 75));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(!strcmp(part(result, "key"), expected_key) && !strcmp(part(result, "secret"), expected_secret));
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_secret(other_secret, 'z');
    CHECK(BR_ABI_REVISION == 1 && strlen("mux") == 3);
    CHECK(strlen(key) == 36 && strlen(other_key) == 36 && strlen(secret) == 75 && strlen(other_secret) == 75);
    CHECK(strstr(secret, "+") && strstr(secret, "/") && strcmp(key, other_key) && strcmp(secret, other_secret));
    CHECK(!strcmp(url, "https://api.mux.com/video/v1/assets"));
    CHECK(!strncmp(known_auth, "Basic ", 6) && strncmp(known_auth, "Basic Basic ", 12));
    CHECK(br_mux_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_mux_init(&d, &error) == 0 && d && !error);
    CHECK(br_mux_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 748 && d->version == 0 && !strcmp(d->name, "Mux"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Mux is a video streaming service that provides APIs for video hosting, live streaming, and video analytics. Mux API keys can be used to access and manage video assets and streaming data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mux"));
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
    char input[256];
    br_results out = scan_text(d, false, key, strlen(key)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s", key);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s\n", secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s\nmux %s\n", key, secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    snprintf(input, sizeof(input), "MUX %s\rMUX %s ", other_key, other_secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 1);
    pair(&out.items[0], other_key, other_secret, false); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s", secret); /* No required trailing delimiter. */
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s\nmux %.74s\n", key, secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux 01234567-89AB-cdef-0123-456789abcdef\nmux %s\n", secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    char gap[160];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "mux", 3); memcpy(gap + 43, key, 36);
    memcpy(gap + 80, "mux ", 4); memcpy(gap + 84, secret, 75); gap[159] = '\n';
    out = scan_text(d, false, gap, 160); CHECK(out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "mux", 3); memcpy(gap + 44, key, 36);
    out = scan_text(d, false, gap, 80); CHECK(out.len == 0); br_results_clear(&out);
    char far[1400];
    memset(far, ' ', sizeof(far));
    memcpy(far, "mux ", 4); memcpy(far + 4, key, 36);
    memcpy(far + 1140, "mux ", 4); memcpy(far + 1144, secret, 75); far[1219] = '\n';
    out = scan_text(d, false, far, 1220); CHECK(out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s\nmux %s\nmux %s\nmux %s\n", key, other_key, secret, other_secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 4);
    pair(&out.items[0], key, secret, false); pair(&out.items[1], key, other_secret, false);
    pair(&out.items[2], other_key, secret, false); pair(&out.items[3], other_key, other_secret, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "mux %s\nmux %s\nmux %s\n", key, key, secret);
    out = scan_text(d, false, input, strlen(input)); CHECK(out.len == 2);
    pair(&out.items[0], key, secret, false); pair(&out.items[1], key, secret, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].raw_v2.data != out.items[1].raw_v2.data);
    br_results_clear(&out);
}

typedef struct { const char *key, *secret, *auth, *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[4]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 4 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 748 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && request->headers[1].value);
    CHECK(!strcmp(request->headers[1].value, reply->auth));
    CHECK(!strncmp(request->headers[1].value, "Basic ", 6) && strncmp(request->headers[1].value, "Basic Basic ", 12));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog mux-offline" : "TruffleHog"));
    steps->borrowed_auth = request->headers[1].value;
    http->response = (br_http_response){.status = reply->status, .body_error = reply->read_error};
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
    CHECK(steps->borrowed_auth && !strcmp(steps->borrowed_auth, steps->rows[http->calls - 1].auth));
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "mux-offline" : NULL}; steps->ctx = &ctx;
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
    char input[160]; snprintf(input, sizeof(input), "mux %s\nmux %s\n", key, secret);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .secret = secret, .auth = known_auth, .status = status,
                              .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        pair(&out.items[0], key, secret, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .secret = secret, .auth = known_auth, .status = statuses[i], .read_error = "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        pair(&out.items[0], key, secret, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .secret = secret, .auth = known_auth, .status = 200,
                              .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = ""};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        pair(&out.items[0], key, secret, false); br_results_clear(&out);
    }
    char cross_auth[192] = {0}, other_cross[192] = {0}, other_auth[192] = {0};
    char *built = NULL; char *error = NULL;
    CHECK(br_http_basic_auth(text(key), text(other_secret), &built, &error) == 0 && built && !error);
    snprintf(cross_auth, sizeof(cross_auth), "%s", built); free(built); built = NULL;
    CHECK(br_http_basic_auth(text(other_key), text(secret), &built, &error) == 0 && built && !error);
    snprintf(other_cross, sizeof(other_cross), "%s", built); free(built); built = NULL;
    CHECK(br_http_basic_auth(text(other_key), text(other_secret), &built, &error) == 0 && built && !error);
    snprintf(other_auth, sizeof(other_auth), "%s", built); free(built);
    char occurrences[320];
    snprintf(occurrences, sizeof(occurrences), "mux %s\nmux %s\nmux %s\nmux %s\n", key, other_key, secret, other_secret);
    script steps = {.count = 4, .suffix = true};
    steps.rows[0] = (row){.key = key, .auth = known_auth, .status = 200, .read_error = "read failed"};
    steps.rows[1] = (row){.key = key, .auth = cross_auth, .status = 401};
    steps.rows[2] = (row){.key = other_key, .auth = other_cross, .status = 204, .read_error = ""};
    steps.rows[3] = (row){.key = other_key, .auth = other_auth, .status = 500};
    br_results out = run(d, occurrences, &steps); CHECK(out.len == 4);
    pair(&out.items[0], key, secret, true); pair(&out.items[1], key, other_secret, false);
    pair(&out.items[2], other_key, secret, true); pair(&out.items[3], other_key, other_secret, false);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "mux %s\nmux %s\n", key, secret);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    pair(&out.items[0], key, secret, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key"); br_results_clear(&caller);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(out);
}

static void own_failure_rollback(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "mux %s\nmux %s\n", key, secret);
    const size_t sizes[] = {37, 36};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_basic = true;
    rc = d->scan(d, &ctx, true, text(input), &out, &error);
    CHECK(!arm_basic && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .secret = secret, .auth = known_auth, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[220]; snprintf(pair, sizeof(pair), "mux %s\nmux %s\nmux %s\n", key, key, secret);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 36, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .secret = secret, .auth = known_auth, .status = 200};
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
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers && !arm_basic);
    return test_finish("Mux");
}
