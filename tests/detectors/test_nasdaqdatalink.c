/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_nasdaqdatalink_init(const br_detector **out, char **error);

static const char prefix[] = "https://data.nasdaq.com/api/v3/datasets/FRED/GDP.csv?api_key=";
static const char suffix[] = "&collapse=annual&rows=6&order=asc&column_index=1";
static const char known[] = "Ab12_cd34-ef56GH7890";
static char other[21];
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_url;

static void fill_key(char *out, char marker)
{
    memset(out, marker, 20);
    out[20] = '\0';
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
        if (arm_http_headers) { arm_http_headers = false; fail_size = sizeof(br_header); fail_after = 1; }
        if (arm_url) {
            arm_url = false;
            fail_size = sizeof(prefix) - 1 + 20 + sizeof(suffix) - 1 + 1;
            fail_after = 1;
        }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static void expect_url(char *out, size_t n, const char *key)
{
    snprintf(out, n, "%s%s%s", prefix, key, suffix);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(other, 'z');
    CHECK(BR_ABI_REVISION == 1 && strlen("nasdaq") == 6 && strcmp("nasdaq", "nasdaqdatalink"));
    CHECK(strlen(known) == 20 && strlen(other) == 20 && strcmp(known, other));
    CHECK(strstr(known, "_") && strstr(known, "-") && !strchr(known, '%'));
    CHECK(!strcmp(prefix, "https://data.nasdaq.com/api/v3/datasets/FRED/GDP.csv?api_key="));
    CHECK(!strcmp(suffix, "&collapse=annual&rows=6&order=asc&column_index=1"));
    CHECK(br_nasdaqdatalink_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_nasdaqdatalink_init(&d, &error) == 0 && d && !error);
    CHECK(br_nasdaqdatalink_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 532 && d->version == 0 && !strcmp(d->name, "NasdaqDataLink"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Nasdaq Data Link provides financial, economic and alternative datasets. The API key can be used to access and retrieve this data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nasdaq") && strcmp(d->keywords[0], "nasdaqdatalink"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 532, expected, "key");
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
    snprintf(input, sizeof(input), "nasdaq %s", known); extraction_case(d, input, known);
    snprintf(input, sizeof(input), "NASDAQ:%s", other); extraction_case(d, input, other);
    snprintf(input, sizeof(input), "nasdaqdatalink %s", known); extraction_case(d, input, known);
    snprintf(input, sizeof(input), "nasdaq%s", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "nasdaq %.19s", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "nasdaq %sa", known); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "nasdaq %s.", known); extraction_case(d, input, known);
    snprintf(input, sizeof(input), "nasdaq abcd+efgh1234567890"); extraction_case(d, input, NULL);
    char gap[128];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "nasdaq", 6); memcpy(gap + 46, known, 20);
    br_results out = test_scan(d, NULL, false, gap, 66); CHECK(out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "nasdaq", 6); memcpy(gap + 47, known, 20);
    out = test_scan(d, NULL, false, gap, 67); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "nasdaq %s\nNasdaq %s\nnasdaq %s", known, other, known);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], known, false); finding(&out.items[1], other, false); finding(&out.items[2], known, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    char expected[192]; expect_url(expected, sizeof(expected), reply->key);
    CHECK(request->detector_type == 532 && request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(request->timeout_ms != 5000);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, expected));
    CHECK(!strchr(request->url, '%') && strstr(request->url, reply->key));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->suffix ? "TruffleHog nasdaqdatalink-offline" : "TruffleHog"));
    for (size_t i = 0; i < request->nheaders; ++i)
        CHECK(strcmp(request->headers[i].name, "Authorization") && strcmp(request->headers[i].name, "Content-Type"));
    steps->borrowed_url = request->url;
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
    char expected[192]; expect_url(expected, sizeof(expected), steps->rows[http->calls - 1].key);
    CHECK(steps->borrowed_url && !strcmp(steps->borrowed_url, expected));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "nasdaqdatalink-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_url);
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
    char input[64]; snprintf(input, sizeof(input), "nasdaq %s", known);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .status = status, .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .status = statuses[i], .read_error = "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = known, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = ""};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], known, false); br_results_clear(&out);
    }
    char occurrences[160];
    snprintf(occurrences, sizeof(occurrences), "nasdaq %s\nNASDAQ %s\nnasdaq %s", known, other, known);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = known, .status = 200, .read_error = "read failed"};
    steps.rows[1] = (row){.key = other, .status = 401};
    steps.rows[2] = (row){.key = known, .status = 204, .read_error = ""};
    br_results out = run(d, occurrences, &steps); CHECK(out.len == 3);
    finding(&out.items[0], known, true); finding(&out.items[1], other, false); finding(&out.items[2], known, true);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "nasdaq %s", known);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], known, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
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
    char input[64]; snprintf(input, sizeof(input), "nasdaq %s", known);
    const size_t sizes[] = {21, 20};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_url = true;
    rc = d->scan(d, &ctx, true, text(input), &out, &error);
    CHECK(!arm_url && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = known, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[128]; snprintf(pair, sizeof(pair), "nasdaq %s\nnasdaq %s", known, known);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 20, .arm_after = 1};
    steps.rows[0] = (row){.key = known, .status = 200};
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
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers && !arm_url);
    return test_finish("NasdaqDataLink");
}
