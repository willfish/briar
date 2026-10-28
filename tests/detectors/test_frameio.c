/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define BLOCK "Aa0Bb1Cc2Dd3Ee4F"
#define OTHER_BLOCK "-Z9y8x7w6v5u4t3S"
static const char key[] = "fio-u-" BLOCK BLOCK BLOCK BLOCK;
static const char other[] = "fio-u-" OTHER_BLOCK OTHER_BLOCK OTHER_BLOCK OTHER_BLOCK;
static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_size;

/* Existing native capture/finding/shared-header/push resources only; never
 * invented heap copies or failure seams for the bounded Authorization value. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
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
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 70 && strlen(other) == 70);
    CHECK(br_frameio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_frameio_init(&d, &error) == 0 && d && !error);
    CHECK(br_frameio_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 199 && d->version == 0 && !strcmp(d->name, "FrameIO") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Frame.io is a video review and collaboration platform. Frame.io API keys can be used to access and manage video projects and assets."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "fio-u-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 199, expected, "key");
    CHECK(r->raw.len == 70 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len); CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void direct_regex_and_fixed_width_boundaries(const br_detector *d)
{
    char input[180], changed[72];
    const char *good[] = {"%s", "'%s'", "FrameIO %s", "-%s-"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, strlen(input), key); }
    extraction_case(d, other, strlen(other), other); /* Hyphens inside payload are legal; no JWT/base64 validation. */
    const char *bad[] = {"_%s", "X%s", "%s_", "%sA"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, strlen(input), NULL); }
    memcpy(changed, key, sizeof(key)); changed[0] = 'F'; extraction_case(d, changed, strlen(changed), NULL);
    memcpy(changed, key, sizeof(key)); changed[4] = 'U'; extraction_case(d, changed, strlen(changed), NULL);
    memcpy(changed, key, sizeof(key)); changed[69] = '\0'; extraction_case(d, changed, strlen(changed), NULL);
    memcpy(changed, key, sizeof(key)); changed[20] = '.'; extraction_case(d, changed, strlen(changed), NULL);
    memcpy(changed, "fio-u-", 6); memset(changed + 6, '_', 64); changed[70] = '\0';
    extraction_case(d, changed, strlen(changed), changed); /* Underscore is a word character. */
    memcpy(changed, "fio-u-", 6); memset(changed + 6, '-', 64); changed[70] = '\0';
    extraction_case(d, changed, strlen(changed), NULL); /* Final non-word hyphen + EOF is NOT a word boundary. */
    snprintf(input, sizeof(input), "%sA", changed); extraction_case(d, input, strlen(input), changed); /* Final hyphen + word char IS a boundary, despite the wider token alphabet. */
    memcpy(changed, key, sizeof(key)); changed[69] = '-';
    extraction_case(d, changed, strlen(changed), NULL);
    snprintf(input, sizeof(input), "%sA", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "%s_", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "%s-", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%s-", key); extraction_case(d, input, strlen(input), key); /* Extra allowed hyphen does NOT require a full-token assertion. */
    int n = snprintf(input, sizeof(input), "%c%s%c", 0, key, 0); CHECK(n == 72); extraction_case(d, input, (size_t)n, key);
    extraction_case(d, "FrameIO", sizeof("FrameIO") - 1, NULL); extraction_case(d, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, rc; bool empty_body; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_auth;
    size_t arm_call, arm_push;
} script;
static void authorization(const char *value, const char *expected)
{
    CHECK(!memcmp(value, "Bearer ", 7) && !memcmp(value + 7, expected, 71) && strlen(value) == 77);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const row *reply = &steps->rows[at];
    CHECK(request->detector_type == 199 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.frame.io/v2/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    authorization(request->headers[1].value, reply->key); steps->borrowed_auth = request->headers[1].value;
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog frameio-offline"));
    static const unsigned char garbage[] = "\0\xff {not JSON} \"status\":401";
    http->response = (br_http_response){.status = reply->status,
        .body = reply->empty_body ? (br_slice){0} : (br_slice){garbage, sizeof(garbage) - 1},
        .body_error = reply->empty_body ? "" : "ignored response body read error"};
    http->send_error = reply->send_error; http->send_rc = reply->rc;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) fail_push_size = steps->arm_push;
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth); authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key);
    steps->borrowed_auth = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "frameio-offline"}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static void occurrences_and_status_only(const br_detector *d)
{
    char input[240]; snprintf(input, sizeof(input), "%s\n%s\n%s", key, other, key);
    row replies[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .empty_body = true},
        {.key = key, .status = 200, .rc = -7, .send_error = "cannot create FrameIO finding"}};
    script steps = {.rows = replies, .count = 3}; br_results out = run(d, input, &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, true); finding(&out.items[1], other, true); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], i == 1 ? other : key, false);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len && !out.items && !out.cap); br_results_clear(&out);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        row reply = {.key = key, .status = statuses[i], .empty_body = i % 2 != 0}; steps = (script){.rows = &reply, .count = 1};
        out = run(d, key, &steps); CHECK(out.len == 1); finding(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    /* The boundary-required following word byte is NOT part of the key/header. */
    char ending_hyphen[71]; memcpy(ending_hyphen, key, sizeof(key)); ending_hyphen[69] = '-';
    snprintf(input, sizeof(input), "%sA", ending_hyphen);
    row edge = {.key = ending_hyphen, .status = 200}; steps = (script){.rows = &edge, .count = 1};
    out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], ending_hyphen, true); br_results_clear(&out);
    char echo[190]; snprintf(echo, sizeof(echo), "out of memory %s echoed %s", key, key);
    const char *errors[] = {echo, "", "cannot append FrameIO finding"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        row reply = {.key = key, .status = 200, .rc = i % 2 ? 1 : -1, .send_error = errors[i]}; steps = (script){.rows = &reply, .count = 1};
        out = run(d, key, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void actual_shared_failures(const br_detector *d)
{
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results out = test_scan(d, &ctx, true, key, strlen(key));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u)); finding(&out.items[0], key, false); br_results_clear(&out);
    }
}
static br_results caller_owned(void)
{
    br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("prior diagnostic"); CHECK(prior.verification_error && br_results_push(&out, &prior) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error, unsigned char *raw, br_json *parts, char *cause)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    CHECK(out->items[0].verified && out->items[0].raw.data == raw && out->items[0].secret_parts == parts && out->items[0].verification_error == cause && !strcmp(cause, "prior diagnostic"));
    free(error); br_results_clear(out);
}
static void own_resources_before_skip_or_suppression(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    const size_t sizes[] = {2 * sizeof(br_span), 71, 70};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1);
        rolled_back(&out, rc, error, raw, parts, cause); /* Actual +1 regex/capture/finding failures BEFORE constructor skip. */
    }
    const row replies[] = {{.key = key, .status = 200}, {.key = other, .status = 200, .rc = 1, .send_error = "suppressed before owned push failure"}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        script steps = {.rows = replies, .count = 1}; fail_part_after = 2;
        int rc = mode == 0 ? invoke(d, input, &steps, &out, &error) : d->scan(d, NULL, mode == 2, text(input), &out, &error);
        CHECK(!fail_part_after); rolled_back(&out, rc, error, raw, parts, cause);
    } /* First result appended OR nil-context skipped; second owned finding fails. */
    br_results out = caller_owned(); out.cap = out.len;
    unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
    script steps = {.rows = replies, .count = 2, .arm_call = 2, .arm_push = 4 * sizeof(br_result)};
    size_t before = allocation_failures; int rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
}

int main(void)
{
    const br_detector *d = descriptor();
    direct_regex_and_fixed_width_boundaries(d);
    occurrences_and_status_only(d);
    actual_shared_failures(d);
    own_resources_before_skip_or_suppression(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_size);
    return test_finish("FrameIO");
}
