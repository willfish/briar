/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define HALF "AbCdEfGhIj0123456789"
static const char key[] = HALF HALF;
static char hyphens[41];
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_shared_setup;

/* Real native ownership/shared-setup resources only. No synthetic heap or
 * formatting failure point exists for the bounded stack request URL. */
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
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, previous < size ? previous : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_shared_setup && !strcmp(name, "key")) {
        arm_shared_setup = false; fail_size = sizeof(br_header); fail_after = 1;
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(hyphens) == 40);
    CHECK(br_extractorapi_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_extractorapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_extractorapi_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 784 && d->version == 0 && !strcmp(d->name, "ExtractorAPI") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "ExtractorAPI is a service for extracting data from various sources. ExtractorAPI keys can be used to access and extract data from these sources."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "extractorapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 784, expected, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input.data, input.len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[320], changed[42]; extraction_case(d, text(key), NULL);
    const char *good[] = {"extractorapi %s", "EXTRACTORAPI='%s'", "ExTrAcToRaPi\r\n%s", "xextractorapi:(%s)", "extractorapi -%s-"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, text(input), key); }
    snprintf(input, sizeof(input), "extractorapi %s", hyphens); extraction_case(d, text(input), hyphens);
    const char *bad[] = {"extractor %s", "extractorapi _%s", "extractorapi %s_", "extractorapi %sA", "extractorapi %.39s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, text(input), NULL); }
    const char invalid[] = "_+/.:";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = invalid[i]; snprintf(input, sizeof(input), "extractorapi %s", changed);
        extraction_case(d, text(input), NULL);
    }
    memset(changed, '0', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "extractorapi %s", changed); extraction_case(d, text(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "extractorapi", 12); memset(input + 12, ' ', gap); memcpy(input + 12 + gap, key, sizeof(key));
        extraction_case(d, text(input), gap == 40 ? key : NULL);
    }
    memcpy(input, "extractorapi", 12); memset(input + 12, ' ', 40); input[30] = '\n'; input[40] = '\r'; memcpy(input + 52, key, sizeof(key));
    extraction_case(d, text(input), key);
    /* Word boundaries are NOT delimiters excluding the entire token alphabet.
     * Backtracking may select a leading/trailing hyphen inside a longer run. */
    memset(changed, 'A', 40); changed[0] = '-'; changed[40] = '\0';
    snprintf(input, sizeof(input), "extractorapi %s", changed); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "extractorapi X%s", changed); extraction_case(d, text(input), changed);
    memset(changed, 'A', 40); changed[39] = '-'; changed[40] = '\0';
    snprintf(input, sizeof(input), "extractorapi %s", changed); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "extractorapi %sZ", changed); extraction_case(d, text(input), changed);
    snprintf(input, sizeof(input), "extractorapi %s-Z", key); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "extractorapi %s %s", key, hyphens); extraction_case(d, text(input), key); /* Consumed keyword is not reused. */
    input[0] = '\0'; memcpy(input + 1, "extractorapi ", 13); memcpy(input + 14, key, 40); input[54] = (char)0xff;
    extraction_case(d, (br_slice){(unsigned char *)input, 55}, key);
    extraction_case(d, (br_slice){0}, NULL);
    snprintf(input, sizeof(input), "extractorapi %s\nEXTRACTORAPI %s\nextractorapi %s", key, hyphens, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], hyphens, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
}

typedef struct { const char *key, *read_error, *send_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url; size_t arm_call, arm_size, arm_after, arm_push;
} script;
static void url_value(const char *actual, const char *expected_key)
{
    char expected[106];
    CHECK(snprintf(expected, sizeof(expected), "https://extractorapi.com/api/v1/extractor?apikey=%s&url=example.com", expected_key) == 105);
    CHECK(actual && strlen(actual) == 105 && !memcmp(actual, expected, sizeof(expected))); /* Includes final NUL. */
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(request->detector_type == 784 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, steps->suffix ? "TruffleHog extractorapi-offline" : "TruffleHog"));
    url_value(request->url, steps->rows[at].key); steps->borrowed_url = request->url;
    row *reply = &steps->rows[at];
    http->response = (br_http_response){.status = reply->status, .body = TEXT("not JSON\0\xff"), .body_error = reply->read_error};
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
    url_value(steps->borrowed_url, steps->rows[http->calls - 1].key); steps->borrowed_url = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "extractorapi-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_url); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static void statuses_suppression_and_url_lifetime(const br_detector *d)
{
    char input[240]; snprintf(input, sizeof(input), "extractorapi %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = status, .read_error = status % 2 ? "ignored body/read failure" : ""};
        br_results out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = statuses[i], .read_error = "ignored"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_shared_setup = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(!arm_shared_setup && !fail_after && allocation_failures == before + 1 && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    snprintf(input, sizeof(input), "extractorapi %s\nEXTRACTORAPI %s\nextractorapi %s", key, hyphens, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 401}; steps.rows[1] = (row){.key = hyphens, .status = 299}; steps.rows[2] = (row){.key = key, .status = 200};
    out = run(d, input, &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], hyphens, true); finding(&out.items[2], key, true); br_results_clear(&out);
    /* Hyphen edges remain original in the query, without full-token validation. */
    char edge[41]; memset(edge, 'A', 40); edge[0] = '-'; edge[40] = '\0';
    snprintf(input, sizeof(input), "extractorapi X%s", edge);
    steps = (script){.count = 1}; steps.rows[0] = (row){.key = edge, .status = 200};
    out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], edge, true); br_results_clear(&out);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key"); free(error); br_results_clear(out);
}
static void own_resources_before_skip_and_suppression(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "extractorapi %s", key);
    const size_t sizes[] = {41, 40};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)}; steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; size_t before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    /* First finding is already appended. A later owned failure must remove
     * that invocation's append, not just the current candidate. */
    snprintf(input, sizeof(input), "extractorapi %s\nextractorapi %s", key, hyphens);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 40, .arm_after = 1}; steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    memcpy(hyphens, key, sizeof(key)); hyphens[6] = '-'; hyphens[23] = '-'; hyphens[31] = '-';
    const br_detector *d = descriptor();
    extraction(d);
    statuses_suppression_and_url_lifetime(d);
    own_resources_before_skip_and_suppression(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_shared_setup);
    return test_finish("ExtractorAPI");
}
