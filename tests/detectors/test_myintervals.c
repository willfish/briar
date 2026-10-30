/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_myintervals_init(const br_detector **out, char **error);

static char key[12], other[12];
static const char url[] = "https://api.myintervals.com/client/";
static const char known[] = "0123456789a";
static const char known_auth[] = "Basic MDEyMzQ1Njc4OWE6WA==";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_basic;

static void fill_key(char *out, unsigned salt)
{
    static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < 11; ++i) out[i] = alphabet[(i + salt) % 36];
    out[11] = '\0';
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
    if (!rc && !strcmp(name, "key")) {
        if (arm_http_headers) { arm_http_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
        if (arm_basic) { arm_basic = false; fail_size = 27; fail_after = 1; }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 5);
    CHECK(BR_ABI_REVISION == 1 && strlen("myintervals") == 11);
    CHECK(strlen(key) == 11 && strlen(other) == 11 && strlen(known) == 11 && strcmp(key, other));
    CHECK(!strcmp(url, "https://api.myintervals.com/client/") && url[strlen(url) - 1] == '/');
    CHECK(!strcmp(known_auth, "Basic MDEyMzQ1Njc4OWE6WA==") && strncmp(known_auth, "Basic Basic ", 12));
    CHECK(br_myintervals_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_myintervals_init(&d, &error) == 0 && d && !error);
    CHECK(br_myintervals_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 688 && d->version == 0 && !strcmp(d->name, "MyIntervals"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "MyIntervals is a project management tool that helps in tracking time, managing tasks, and organizing projects. MyIntervals API keys can be used to access and modify project data and user information."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "myintervals"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 688, expected, "key");
    CHECK(result->verified == verified && !result->verification_error && !result->extra_data && !result->raw_v2.data);
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[192];
    extraction_case(d, known, NULL);
    snprintf(input, sizeof(input), "myintervals %s", known); extraction_case(d, input, known);
    snprintf(input, sizeof(input), "MYINTERVALS:%s", key); extraction_case(d, input, key);
    snprintf(input, sizeof(input), "myintervals%s", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "myintervals %.10s", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "myintervals %sa", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "myintervals 0123456789A"); extraction_case(d, input, NULL);
    char gap[128];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "myintervals", 11); memcpy(gap + 51, known, 11);
    br_results out = test_scan(d, NULL, false, gap, 62); CHECK(out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "myintervals", 11); memcpy(gap + 52, known, 11);
    out = test_scan(d, NULL, false, gap, 63); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "myintervals %s\nMyIntervals %s\nmyintervals %s", key, other, key);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *auth, *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 688 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(request->headers[1].value && !strcmp(request->headers[1].value, reply->auth));
    CHECK(!strncmp(request->headers[1].value, "Basic ", 6) && strncmp(request->headers[1].value, "Basic Basic ", 12));
    CHECK(strncmp(request->headers[1].value, "Bearer ", 7) && strncmp(request->headers[1].value, "Token token=", 12));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog myintervals-offline" : "TruffleHog"));
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

static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "myintervals-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth);
    return rc;
}

static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_and_send_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "myintervals %s", known);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .auth = known_auth, .status = status, .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .auth = known_auth, .status = statuses[i], .read_error = "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .auth = known_auth, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = ""};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, false); br_results_clear(&out);
    }
    char other_auth[64] = {0};
    char *built = NULL; char *error = NULL;
    CHECK(br_http_basic_auth(text(other), (br_slice){(const unsigned char *)"X", 1}, &built, &error) == 0 && built && !error);
    snprintf(other_auth, sizeof(other_auth), "%s", built); free(built);
    char occurrences[160];
    snprintf(occurrences, sizeof(occurrences), "myintervals %s\nMYINTERVALS %s\nmyintervals %s", known, other, known);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = known, .auth = known_auth, .status = 200, .read_error = "read failed"};
    steps.rows[1] = (row){.key = other, .auth = other_auth, .status = 401};
    steps.rows[2] = (row){.key = known, .auth = known_auth, .status = 204, .read_error = ""};
    br_results out = run(d, occurrences, &steps); CHECK(out.len == 3);
    finding(&out.items[0], known, true); finding(&out.items[1], other, false); finding(&out.items[2], known, true);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "myintervals %s", known);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 2;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
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
    char input[64]; snprintf(input, sizeof(input), "myintervals %s", known);
    const size_t sizes[] = {12, 11};
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
    steps.rows[0] = (row){.key = known, .auth = known_auth, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[96]; snprintf(pair, sizeof(pair), "myintervals %s\nmyintervals %s", known, known);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 11, .arm_after = 1};
    steps.rows[0] = (row){.key = known, .auth = known_auth, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, pair, &steps, &out, &error);
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
    return test_finish("MyIntervals");
}
