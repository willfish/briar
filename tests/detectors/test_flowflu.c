/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk0Ll1Mm2Nn3Oo4Pp5Qq6";
static const char other[] = "Rr7Ss8Tt9Uu0Vv1Ww2Xx3Yy4Zz5Aa6Bb7Cc8Dd9Ee0Ff1Gg2Hh3";
static const char account[] = "WorkONE", other_account[] = "workONE";
static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_size;

/* Existing native resources only; no added URL/allocation/cap failure seams. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 51 && strlen(other) == 51);
    CHECK(br_flowflu_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:flowflu)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_flowflu_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_flowflu_init(&d, &error) == 0 && d && !error);
    CHECK(br_flowflu_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 265 && d->version == 0 && !strcmp(d->name, "FlowFlu") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FlowFlu is a service used for managing customer relationships and projects. FlowFlu API keys can be used to access and manipulate CRM data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "flowflu"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 265, expected, "key"); /* Required account stays hidden even when verified. */
    CHECK(r->raw.len == 51 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len); CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void tokens(const br_detector *d, const char *secret, const char *workspace, bool accepted)
{
    char input[200]; snprintf(input, sizeof(input), "FlOwFlU %s\nAcCoUnT %s", secret, workspace);
    extraction_case(d, input, strlen(input), accepted ? secret : NULL);
}
static void independent_prefixes_and_bounds(const br_detector *d)
{
    char input[220], changed_key[53];
    tokens(d, key, account, true); tokens(d, "000000000000000000000000000000000000000000000000000", "0000", true);
    tokens(d, key, "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9", true); /* Account max 30, mixed case, no filtering. */
    tokens(d, key, "abc", false); tokens(d, key, "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9K", false);
    snprintf(input, sizeof(input), "flowflu %s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "account %s", account); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "flowlu %s\naccount %s", key, account); extraction_case(d, input, strlen(input), NULL); /* Do NOT correct dispatch typo. */
    snprintf(input, sizeof(input), "account %s\naccount %s", key, account); extraction_case(d, input, strlen(input), NULL); /* account is NOT a key prefix. */
    snprintf(input, sizeof(input), "%s\nflowflu %s", account, key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "flowflu %s\nflowflu %s", key, account); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preFLOWFLU %s\npreACCOUNT %s", key, account); extraction_case(d, input, strlen(input), key);
    memcpy(changed_key, key, sizeof(key)); changed_key[50] = '\0'; tokens(d, changed_key, account, false);
    memcpy(changed_key, key, sizeof(key)); changed_key[51] = 'a'; changed_key[52] = '\0'; tokens(d, changed_key, account, false);
    memcpy(changed_key, key, sizeof(key)); changed_key[20] = '_'; tokens(d, changed_key, account, false);
    const char *bad[] = {"flowflu _%s\naccount %s", "flowflu %s_\naccount %s", "flowflu %s\naccount _%s", "flowflu %s\naccount %s_"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key, account); extraction_case(d, input, strlen(input), NULL); }
    for (size_t gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "flowflu%*s%s\naccount %s", (int)gap, "", key, account);
        CHECK(n > 0); extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
        n = snprintf(input, sizeof(input), "flowflu %s\naccount%*s%s", key, (int)gap, "", account);
        CHECK(n > 0); extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "flowflu%c%s\naccount%c%s", 0, key, 0, account);
    CHECK(n > 0); extraction_case(d, input, (size_t)n, key);
    char distant[2400]; size_t at = (size_t)snprintf(distant, sizeof(distant), "flowflu %s\n", key);
    memset(distant + at, ' ', 2048); at += 2048;
    n = snprintf(distant + at, sizeof(distant) - at, "\naccount %s", account); CHECK(n > 0); at += (size_t)n;
    CHECK(at > 1024); extraction_case(d, distant, at, key);
    extraction_case(d, NULL, 0, NULL);
}

typedef struct { const char *key, *account; int status; br_slice body; const char *read_error, *send_error; int rc; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; unsigned char *body;
    size_t arm_call, arm_push;
} script;
static void url_value(const row *reply, const char *url)
{
    char expected[138]; int n = snprintf(expected, sizeof(expected), "https://%s.flowlu.com/api/v1/module/crm/lead/list?api_key=%s", reply->account, reply->key);
    CHECK(n == 107 + (int)strlen(reply->account) && n >= 111 && n <= 137 && !memcmp(url, expected, (size_t)n + 1));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const row *reply = &steps->rows[at];
    CHECK(request->detector_type == 265 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog flowflu-offline"));
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
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "flowflu-offline"}; steps->ctx = &ctx;
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
    char input[150]; if (!reply->key) reply->key = key; if (!reply->account) reply->account = account;
    snprintf(input, sizeof(input), "flowflu %s\naccount %s", reply->key, reply->account);
    script steps = {.rows = reply, .count = 1}; return run(d, input, &steps);
}
static void read_all_statuses_and_binary_marker(const br_detector *d)
{
    const struct { int status; br_slice body; const char *read_error; bool kept, verified; } cases[] = {
        {200, TEXT("total_result"), NULL, true, true}, {200, TEXT("unrelated total_result=-999"), NULL, true, true},
        {204, TEXT(""), NULL, true, false}, {299, TEXT("\0\xff" "total_result\0"), NULL, true, true},
        {200, TEXT("total_\0result"), NULL, true, false}, {200, TEXT("TOTAL_RESULT"), NULL, true, false},
        {200, TEXT("total result"), NULL, true, false}, {200, TEXT("{\"total\\u005fresult\":1}"), NULL, true, false},
        {201, TEXT("{\"total_result\":false}"), NULL, true, true},
        {199, TEXT("total_result"), NULL, true, false}, {300, TEXT("total_result"), NULL, true, false},
        {401, TEXT("total_result"), NULL, true, false}, {403, TEXT("total_result"), NULL, true, false}, {500, TEXT("total_result"), NULL, true, false},
        {200, TEXT("total_result"), "truncated", false, false}, {403, TEXT("total_result"), "", false, false},
        {401, TEXT("none"), "read failed", false, false}, {500, TEXT("none"), "read failed", false, false},
        {200, TEXT(""), "", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        row reply = {.status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error};
        br_results out = one(d, &reply); CHECK(out.len == (cases[i].kept ? 1u : 0u));
        if (out.len) finding(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    char echo[150]; snprintf(echo, sizeof(echo), "out of memory %s and %s", key, account);
    const char *errors[] = {echo, "", "cannot create FlowFlu finding"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        row reply = {.status = 200, .body = TEXT("total_result"), .read_error = i ? "" : "failed reader", .send_error = errors[i], .rc = i % 2 ? 1 : -7};
        br_results out = one(d, &reply); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *bounds[] = {"A1b2", "Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9"};
    for (size_t i = 0; i < sizeof(bounds) / sizeof(*bounds); ++i) {
        row reply = {.account = bounds[i], .status = 200, .body = TEXT("total_result")};
        br_results out = one(d, &reply); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
    } /* Complete original-case URLs at both 111/137-byte limits, through release. */
}
static void occurrence_products(const br_detector *d)
{
    char input[350]; snprintf(input, sizeof(input), "flowflu %s\nFLOWFLU %s\nflowflu %s\naccount %s\nACCOUNT %s\naccount %s", key, other, key, account, other_account, account);
    const row rows[] = {
        {.key = key, .account = account, .status = 200, .body = TEXT("total_result")},
        {.key = key, .account = other_account, .status = 201, .body = TEXT("total_result")},
        {.key = key, .account = account, .status = 200, .body = TEXT("total_result")},
        {.key = other, .account = account, .status = 299, .body = TEXT("total_result")},
        {.key = other, .account = other_account, .status = 200, .body = TEXT("total_result"), .read_error = ""},
        {.key = other, .account = account, .status = 500, .body = TEXT("none"), .read_error = "failed reader"},
        {.key = key, .account = account, .status = 200, .body = TEXT("none")},
        {.key = key, .account = other_account, .status = 200, .body = TEXT("total_result"), .read_error = "", .send_error = "suppressed", .rc = 1},
        {.key = key, .account = account, .status = 200, .body = TEXT("total_result")},
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
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static void actual_shared_failures(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "flowflu %s\naccount %s", key, account);
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
    char input[160]; snprintf(input, sizeof(input), "flowflu %s\naccount %s\naccount %s", key, account, other_account);
    const size_t sizes[] = {2 * sizeof(br_span), 52, sizeof(account)};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1);
        rolled_back(&out, rc, error, raw, parts, cause);
    } /* Actual +1 regex and BOTH capture resources precede constructor skip. */
    for (int mode = 0; mode < 5; ++mode) {
        row first = {.key = key, .account = account, .status = 200, .body = TEXT("total_result"), .read_error = mode == 3 ? "" : NULL,
            .send_error = mode == 4 ? "suppressed before next finding failure" : NULL, .rc = mode == 4 ? 1 : 0};
        script steps = {.rows = &first, .count = 1};
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        fail_part_after = 2;
        int rc = mode == 1 || mode == 2 ? d->scan(d, NULL, mode == 2, text(input), &out, &error) : invoke(d, input, &steps, &out, &error);
        CHECK(!fail_part_after); rolled_back(&out, rc, error, raw, parts, cause);
    } /* Second finding failure after first appended, skipped, DROPPED or false-KEPT. */
    for (int dropped_first = 0; dropped_first < 2; ++dropped_first) {
        const row replies[] = {
            {.key = key, .account = account, .status = 200, .body = TEXT("total_result"), .read_error = dropped_first ? "" : NULL},
            {.key = key, .account = other_account, .status = 200, .body = TEXT("total_result"), .read_error = "", .send_error = "suppressed before owned push failure", .rc = 1},
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
    independent_prefixes_and_bounds(d);
    read_all_statuses_and_binary_marker(d);
    occurrence_products(d);
    actual_shared_failures(d);
    own_resources_before_skip_drop_suppression(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_size);
    return test_finish("FlowFlu");
}
