/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "ghij0123klmn4567opqr8901stuv2345";
static const char other[] = "wxyz6789abcd0123efgh4567ijkl8901";
static const char id[] = "m9n8p7q6", other_id[] = "r5s4t3u2";
static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_size;

/* Only real existing native resources; no new URL/cap/allocation seams. */
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
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32 && strlen(id) == 8 && strlen(other_id) == 8);
    CHECK(br_flightstats_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:flightstats)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_flightstats_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_flightstats_init(&d, &error) == 0 && d && !error);
    CHECK(br_flightstats_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 642 && d->version == 0 && !strcmp(d->name, "Flightstats") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Flightstats provides APIs for accessing flight data and statistics. Flightstats API keys can be used to retrieve and manipulate flight-related information."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "flightstats"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 642, expected, "key"); /* Required ID stays hidden, including verified output. */
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len); CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void tokens(const br_detector *d, const char *secret, const char *app_id, bool accepted)
{
    char input[180]; snprintf(input, sizeof(input), "FlIgHtStAtS %s\nFLIGHTSTATS %s", secret, app_id);
    extraction_case(d, input, strlen(input), accepted ? secret : NULL);
}
static void independent_extraction(const br_detector *d)
{
    char input[200], changed_key[34], changed_id[10];
    tokens(d, key, id, true); tokens(d, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "zzzzzzzz", true); /* Lower ALNUM, not hex/entropy validation. */
    snprintf(input, sizeof(input), "flightstats %s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "flightstats %s", id); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%s\nflightstats %s", key, id); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%s\nflightstats %s", id, key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "flightstats %s %s", key, id); extraction_case(d, input, strlen(input), key); /* Independent prefixes may share one keyword occurrence. */
    memcpy(changed_key, key, sizeof(key)); changed_key[0] = 'A'; tokens(d, changed_key, id, false);
    memcpy(changed_id, id, sizeof(id)); changed_id[0] = 'A'; tokens(d, key, changed_id, false);
    memcpy(changed_key, key, sizeof(key)); changed_key[31] = '\0'; tokens(d, changed_key, id, false);
    memcpy(changed_id, id, sizeof(id)); changed_id[7] = '\0'; tokens(d, key, changed_id, false);
    memcpy(changed_key, key, sizeof(key)); changed_key[32] = 'a'; changed_key[33] = '\0'; tokens(d, changed_key, id, false);
    memcpy(changed_id, id, sizeof(id)); changed_id[8] = 'a'; changed_id[9] = '\0'; tokens(d, key, changed_id, false);
    const char *bad[] = {"flightstats _%s\nflightstats %s", "flightstats %s_\nflightstats %s", "flightstats %s\nflightstats _%s", "flightstats %s\nflightstats %s_"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key, id); extraction_case(d, input, strlen(input), NULL); }
    for (size_t gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "flightstats%*s%s\nflightstats %s", (int)gap, "", key, id);
        CHECK(n > 0); extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
        n = snprintf(input, sizeof(input), "flightstats %s\nflightstats%*s%s", key, (int)gap, "", id);
        CHECK(n > 0); extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "flightstats%c%s\nflightstats%c%s", 0, key, 0, id);
    CHECK(n > 0); extraction_case(d, input, (size_t)n, key);
    char distant[2400]; size_t at = (size_t)snprintf(distant, sizeof(distant), "flightstats %s\n", key);
    memset(distant + at, ' ', 2048); at += 2048;
    n = snprintf(distant + at, sizeof(distant) - at, "\nflightstats %s", id); CHECK(n > 0); at += (size_t)n;
    CHECK(at > 1024); extraction_case(d, distant, at, key); /* Engine hint, never local span cap. */
    extraction_case(d, NULL, 0, NULL);
}

typedef struct { const char *key, *id; int status; br_slice body; const char *read_error, *send_error; int rc; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; unsigned char *body;
    size_t arm_call, arm_push;
} script;
static void url_value(const row *reply, const char *url)
{
    char expected[126]; int n = snprintf(expected, sizeof(expected), "https://api.flightstats.com/flex/aircraft/rest/v1/json/availableFields?appId=%s&appKey=%s", reply->id, reply->key);
    CHECK(n == 125 && !memcmp(url, expected, 126));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const row *reply = &steps->rows[at];
    CHECK(request->detector_type == 642 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog flightstats-offline"));
    url_value(reply, request->url); steps->borrowed_url = request->url;
    if (reply->body.len) { steps->body = malloc(reply->body.len); CHECK(steps->body); memcpy(steps->body, reply->body.data, reply->body.len); }
    http->response = (br_http_response){.status = reply->status, .body = {steps->body, reply->body.len}, .body_error = reply->read_error};
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
    CHECK(steps->borrowed_url); url_value(&steps->rows[http->calls - 1], steps->borrowed_url);
    if (steps->body) memset(steps->body, '!', response->body.len);
    free(steps->body); steps->body = NULL; steps->borrowed_url = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "flightstats-offline"}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url && !steps->body); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static br_results one(const br_detector *d, row *reply)
{
    char input[100]; snprintf(input, sizeof(input), "flightstats %s\nflightstats %s", key, id);
    reply->key = key; reply->id = id; script steps = {.rows = reply, .count = 1}; return run(d, input, &steps);
}
static void read_all_statuses_and_binary_markers(const br_detector *d)
{
    const struct { int status; br_slice body; const char *read_error; bool kept, verified; } cases[] = {
        {200, TEXT("id"), NULL, true, true}, {200, TEXT("invalid"), NULL, true, true},
        {204, TEXT(""), NULL, true, false}, {299, TEXT("\0\xffid\0"), NULL, true, true},
        {200, TEXT("i\0d"), NULL, true, false}, {200, TEXT("ID"), NULL, true, false},
        {200, TEXT("i d"), NULL, true, false}, {200, TEXT("{\"i\\u0064\":1}"), NULL, true, false},
        {403, TEXT("before application is not active after"), NULL, true, true},
        {403, TEXT("\0\xff" "application is not active\0"), NULL, true, true},
        {403, TEXT("id"), NULL, true, false}, {200, TEXT("application is not active"), NULL, true, false},
        {401, TEXT("application is not active"), NULL, true, false}, {500, TEXT("id application is not active"), NULL, true, false},
        {199, TEXT("id"), NULL, true, false}, {300, TEXT("id"), NULL, true, false},
        {403, TEXT("Application is not active"), NULL, true, false}, {403, TEXT("application  is not active"), NULL, true, false},
        {200, TEXT("id"), "truncated", false, false}, {403, TEXT("application is not active"), "", false, false},
        {401, TEXT("id"), "read failed", false, false}, {500, TEXT("none"), "read failed", false, false},
        {200, TEXT(""), "", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        row reply = {.status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error};
        br_results out = one(d, &reply); CHECK(out.len == (cases[i].kept ? 1u : 0u));
        if (out.len) finding(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    char echo[140]; snprintf(echo, sizeof(echo), "out of memory %s and %s", key, id);
    const char *errors[] = {echo, "", "cannot create Flightstats finding"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        row reply = {.status = i == 2 ? 403 : 200, .body = TEXT("id application is not active"), .read_error = i ? "" : "failed reader", .send_error = errors[i], .rc = i % 2 ? 1 : -7};
        br_results out = one(d, &reply); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    } /* Failed Do suppresses even populated read errors: KEEP, never DROP/setter/classifier. */
}
static void occurrence_products(const br_detector *d)
{
    char input[300]; snprintf(input, sizeof(input), "flightstats %s\nFLIGHTSTATS %s\nflightstats %s\nflightstats %s\nFLIGHTSTATS %s\nflightstats %s", key, other, key, id, other_id, id);
    const row rows[] = {
        {.key = key, .id = id, .status = 200, .body = TEXT("id")},
        {.key = key, .id = other_id, .status = 403, .body = TEXT("application is not active")},
        {.key = key, .id = id, .status = 200, .body = TEXT("id")},
        {.key = other, .id = id, .status = 201, .body = TEXT("id")},
        {.key = other, .id = other_id, .status = 200, .body = TEXT("id"), .read_error = ""},
        {.key = other, .id = id, .status = 500, .body = TEXT("none"), .read_error = "failed reader"},
        {.key = key, .id = id, .status = 200, .body = TEXT("none")},
        {.key = key, .id = other_id, .status = 403, .body = TEXT("application is not active"), .read_error = "", .send_error = "suppressed", .rc = 1},
        {.key = key, .id = id, .status = 200, .body = TEXT("id")},
    };
    script steps = {.rows = rows, .count = 9}; br_results out = run(d, input, &steps); CHECK(out.len == 7);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], i == 3 ? other : key, i < 4 || i == 6);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 9);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], i / 3 == 1 ? other : key, false);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len && !out.items && !out.cap); br_results_clear(&out);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void actual_shared_failures(const br_detector *d)
{
    char input[100]; snprintf(input, sizeof(input), "flightstats %s\nflightstats %s", key, id);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results out = test_scan(d, &ctx, true, input, strlen(input));
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
static void own_resources_before_skip_drop_suppression(const br_detector *d)
{
    char input[140]; snprintf(input, sizeof(input), "flightstats %s\nflightstats %s\nflightstats %s", key, id, other_id);
    const size_t sizes[] = {2 * sizeof(br_span), 33, 9};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1);
        rolled_back(&out, rc, error, raw, parts, cause); /* Regex +1 and BOTH capture resources before nil-context skip. */
    }
    for (int mode = 0; mode < 5; ++mode) {
        row first = {.key = key, .id = id, .status = 200, .body = TEXT("id"), .read_error = mode == 3 ? "" : NULL,
            .send_error = mode == 4 ? "suppressed before next finding failure" : NULL, .rc = mode == 4 ? 1 : 0};
        script steps = {.rows = &first, .count = 1};
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        fail_part_after = 2; /* Second finding failure after first appended, skipped, DROPPED or false-KEPT. */
        int rc = mode == 1 || mode == 2 ? d->scan(d, NULL, mode == 2, text(input), &out, &error) : invoke(d, input, &steps, &out, &error);
        CHECK(!fail_part_after); rolled_back(&out, rc, error, raw, parts, cause);
    }
    for (int dropped_first = 0; dropped_first < 2; ++dropped_first) {
        const row replies[] = {
            {.key = key, .id = id, .status = 200, .body = TEXT("id"), .read_error = dropped_first ? "" : NULL},
            {.key = key, .id = other_id, .status = 403, .body = TEXT("application is not active"), .read_error = "", .send_error = "suppressed before owned push failure", .rc = 1},
        };
        br_results out = caller_owned(); out.cap = out.len;
        unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        script steps = {.rows = replies, .count = 2, .arm_call = 2, .arm_push = (dropped_first ? 2u : 4u) * sizeof(br_result)};
        size_t before = allocation_failures; int rc = invoke(d, input, &steps, &out, &error);
        CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
    }
}

int main(void)
{
    const br_detector *d = descriptor();
    independent_extraction(d);
    read_all_statuses_and_binary_markers(d);
    occurrence_products(d);
    actual_shared_failures(d);
    own_resources_before_skip_drop_suppression(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_size);
    return test_finish("Flightstats");
}
