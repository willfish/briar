/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "0123abcd.0123456789abcdef0123456789abcdef012";
static const char other[] = "89abcdef.fedcba9876543210fedcba9876543210abc";
static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_size;

/* Exercise existing native resources, never added bounded-URL/auth/API seams. */
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
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 44 && strlen(other) == 44);
    CHECK(br_fibery_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:fibery)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_fibery_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_fibery_init(&d, &error) == 0 && d && !error);
    CHECK(br_fibery_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 808 && d->version == 0 && !strcmp(d->name, "Fibery") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Fibery is a work management platform that combines various tools for project management, knowledge management, and software development. Fibery API tokens can be used to access and modify data within a Fibery workspace."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], ".fibery.io"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified, const char *cause)
{
    test_key_result(r, 808, expected, "key"); /* Domain is REQUIRED but never published. */
    CHECK(r->raw.len == 44 && r->verified == verified && (r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
}
static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len); CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void token_case(const br_detector *d, const char *token, bool accepted)
{
    char input[150]; snprintf(input, sizeof(input), "FiBeRy %s\nWork-ONE.fibery.io", token);
    extraction_case(d, input, strlen(input), accepted ? token : NULL);
}
static void keys_and_no_local_span_limit(const br_detector *d)
{
    char input[300], changed[46];
    const char *good[] = {"fibery %s\nWork-ONE.fibery.io", "FIBERY='%s'\nWork-ONE.fibery.io", "prefibery\r\n%s\nWork-ONE.fibery.io", "fibery-%s-\nWork-ONE.fibery.io"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, strlen(input), key); }
    /* Dispatch is .fibery.io, NOT the private key prefix. Required domain also
     * remains required in NoV, and a dispatch hit does not invent a key prefix. */
    snprintf(input, sizeof(input), "fibery %s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%s\nWork-ONE.fibery.io", key); extraction_case(d, input, strlen(input), NULL);
    extraction_case(d, "Work-ONE.fibery.io", sizeof("Work-ONE.fibery.io") - 1, NULL);
    const char *bad[] = {"fibery _%s\nWork-ONE.fibery.io", "fibery %s_\nWork-ONE.fibery.io", "fibery X%s\nWork-ONE.fibery.io", "fibery %sa\nWork-ONE.fibery.io"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, strlen(input), NULL); }
    const size_t positions[] = {0, 7, 9, 43};
    for (size_t i = 0; i < sizeof(positions) / sizeof(*positions); ++i) { memcpy(changed, key, sizeof(key)); changed[positions[i]] = 'A'; token_case(d, changed, false); }
    const char dots[] = {'x', '-', '_'};
    for (size_t i = 0; i < sizeof(dots); ++i) { memcpy(changed, key, sizeof(key)); changed[8] = dots[i]; token_case(d, changed, false); }
    memcpy(changed, key, sizeof(key)); changed[43] = '\0'; token_case(d, changed, false);
    memcpy(changed, key, sizeof(key)); changed[44] = 'a'; changed[45] = '\0'; token_case(d, changed, false);
    memset(changed, '0', 44); changed[8] = '.'; changed[44] = '\0'; token_case(d, changed, true); /* No entropy/hex normalization filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "fibery%*s%s\nWork-ONE.fibery.io", (int)gap, "", key);
        CHECK(n > 0 && (size_t)n < sizeof(input)); extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "fibery%c%s\nWork-ONE.fibery.io", 0, key);
    CHECK(n > 0); extraction_case(d, input, (size_t)n, key);
    char distant[2300]; size_t at = (size_t)snprintf(distant, sizeof(distant), "fibery %s\n", key);
    memset(distant + at, ' ', 2048); at += 2048;
    memcpy(distant + at, "\nRemote.fibery.io", sizeof("\nRemote.fibery.io")); at += sizeof("\nRemote.fibery.io") - 1;
    CHECK(at > 1024); extraction_case(d, distant, at, key);
    extraction_case(d, NULL, 0, NULL);
}

typedef struct { const char *key, *domain, *send_error; int status, rc; bool empty_body; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_auth; char *owned_error;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;
static void request_values(const row *reply, const char *url, const char *authorization)
{
    char expected_url[110], expected_auth[60];
    int n = snprintf(expected_url, sizeof(expected_url), "https://%s.fibery.io/api/commands", reply->domain);
    CHECK(n == (int)strlen(reply->domain) + 31 && n <= 94 && !memcmp(url, expected_url, (size_t)n + 1));
    n = snprintf(expected_auth, sizeof(expected_auth), "Token %s", reply->key);
    CHECK(n == 50 && !memcmp(authorization, expected_auth, 51));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const row *reply = &steps->rows[at];
    CHECK(request->detector_type == 808 && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "POST") && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog fibery-offline"));
    request_values(reply, request->url, request->headers[1].value);
    steps->borrowed_url = request->url; steps->borrowed_auth = request->headers[1].value;
    static const unsigned char garbage[] = "\0\xff {not JSON} \"status\":401";
    http->response = (br_http_response){.status = reply->status,
        .body = reply->empty_body ? (br_slice){0} : (br_slice){garbage, sizeof(garbage) - 1},
        .body_error = reply->empty_body ? "" : "ignored body/read/drain failure"};
    http->send_error = reply->send_error; http->send_rc = reply->rc;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->owned_error = *error;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && steps->borrowed_auth);
    request_values(&steps->rows[http->calls - 1], steps->borrowed_url, steps->borrowed_auth);
    /* Output must already own the sanitized diagnostic before release. The
     * fixture leaves allocation ownership with its caller, poisoning only bytes. */
    if (steps->owned_error) memset(steps->owned_error, '!', strlen(steps->owned_error));
    steps->borrowed_url = steps->borrowed_auth = NULL; steps->owned_error = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "fibery-offline"}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url && !steps->borrowed_auth && !steps->owned_error);
    return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static br_results one(const br_detector *d, const row *reply)
{
    char input[160]; snprintf(input, sizeof(input), "fibery %s\n%s.fibery.io", reply->key, reply->domain);
    script steps = {.rows = reply, .count = 1}; br_results out = run(d, input, &steps); CHECK(out.len == 1); return out;
}

static void domains(const br_detector *d)
{
    const struct { const char *input, *captured; } cases[] = {
        {"https://Work-ONE.fibery.io/path", "Work-ONE"}, {"http://Work-TWO.fibery.io", "Work-TWO"},
        {"HTTPS://MiXeD.fibery.io", "MiXeD"}, {"-.fibery.io", "-"}, {"-edge-.fibery.io", "-edge-"},
        {"prefix.Space.fibery.io.evil", "Space"}, {"One.fibery.ioevil", "One"}, {"under_score.fibery.io", "score"},
        {"One.fibery.io/path Two.fibery.io", "One"}, {"One.fibery.io/\rTwo.fibery.io", "One"},
        {"One.FiBeRy.io", NULL}, {"One.fibery.IO", NULL}, {"OneXfibery.io", NULL}, {"One.fiberyXio", NULL},
        {".fibery.io", NULL}, {"___.fibery.io", NULL},
    };
    char input[300];
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), "fibery %s\n%s", key, cases[i].input);
        row reply = {.key = key, .domain = cases[i].captured, .status = 200}; script steps = {.rows = &reply, .count = cases[i].captured ? 1u : 0u};
        br_results out = run(d, input, &steps); CHECK(out.len == steps.count);
        if (out.len) finding(&out.items[0], key, true, NULL);
        br_results_clear(&out);
    }
    char longest[64], too_long[65]; memset(longest, 'B', 63); longest[63] = '\0'; too_long[0] = 'A'; memcpy(too_long + 1, longest, sizeof(longest));
    for (int i = 0; i < 2; ++i) {
        snprintf(input, sizeof(input), "fibery %s\n%s.fibery.io", key, i ? too_long : longest);
        row reply = {.key = key, .domain = longest, .status = 200}; script steps = {.rows = &reply, .count = 1};
        br_results out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, true, NULL); br_results_clear(&out);
    } /* Unanchored 64-byte label captures its final 63, not rejection/truncation of a captured domain. */
}

static void unique_products_and_statuses(const br_detector *d)
{
    char input[350]; snprintf(input, sizeof(input), "fibery %s\nFIBERY %s\nfibery %s\nSpace.fibery.io space.fibery.io\nSpace.fibery.io", key, other, key);
    const row rows[] = {
        {.key = key, .domain = "Space", .status = 200}, {.key = key, .domain = "space", .status = 401},
        {.key = other, .domain = "Space", .status = 200}, {.key = other, .domain = "space", .status = 200},
    };
    script steps = {.rows = rows, .count = 4}; br_results out = run(d, input, &steps); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) finding(&out.items[i], i < 2 ? key : other, i != 1, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) finding(&out.items[i], i < 2 ? key : other, false, NULL);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) finding(&out.items[i], i < 2 ? key : other, false, "net/http: nil Context");
    br_results_clear(&out);
    /* Slash tail consumes only the remainder of THAT line. */
    snprintf(input, sizeof(input), "fibery %s\nOne.fibery.io/path Hidden.fibery.io\nThree.fibery.io", key);
    const row tail[] = {{.key = key, .domain = "One", .status = 200}, {.key = key, .domain = "Three", .status = 200}};
    steps = (script){.rows = tail, .count = 2}; out = run(d, input, &steps); CHECK(out.len == 2);
    finding(&out.items[0], key, true, NULL); finding(&out.items[1], key, true, NULL); br_results_clear(&out);
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 301, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        row reply = {.key = key, .domain = "Work-ONE", .status = statuses[i], .empty_body = i % 2 != 0};
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        out = one(d, &reply); finding(&out.items[0], key, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause); br_results_clear(&out);
    }
}

static void retained_causes_and_redaction_order(const br_detector *d)
{
    char diagnostic[220]; snprintf(diagnostic, sizeof(diagnostic), "upstream %s then 0123abcd again %s", key, key);
    row reply = {.key = key, .domain = "0123abcd", .status = 200, .rc = -7, .send_error = diagnostic};
    br_results out = one(d, &reply); finding(&out.items[0], key, false, "upstream [REDACTED] then [REDACTED] again [REDACTED]"); br_results_clear(&out);
    snprintf(diagnostic, sizeof(diagnostic), "echo %s and REDACTED", key);
    reply = (row){.key = key, .domain = "REDACTED", .status = 200, .rc = 1, .send_error = diagnostic};
    out = one(d, &reply); finding(&out.items[0], key, false, "echo [[REDACTED]] and [REDACTED]"); br_results_clear(&out);
    const char *errors[] = {"", "cannot create Fibery finding", "out of memory constructing HTTP headers", "unsupported: native curl HTTP client profile", "failed to make request: do not unwrap this injected cause"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reply = (row){.key = key, .domain = "Work-ONE", .status = 200, .rc = i % 2 ? 1 : -1, .send_error = errors[i]};
        out = one(d, &reply); finding(&out.items[0], key, false, errors[i]); br_results_clear(&out);
    } /* A fake PUBLIC 200 above is not proof of native PUBLIC support. Never fall back to SANE. */
    char input[160]; snprintf(input, sizeof(input), "fibery %s\nContext.fibery.io", key);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "net/http: nil [REDACTED]"); br_results_clear(&out);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void actual_shared_setup_failures(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "fibery %s\nWork-ONE.fibery.io", key);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "out of memory constructing HTTP headers", "invalid HTTP user agent", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = i ? &transport : NULL, .cancelled = i == 1 ? cancelled : i == 2 ? fail_headers : NULL,
            .user_agent = i == 3 ? "bad\ragent" : NULL, .deadline_monotonic_ms = i == 4 ? 1 : 0};
        size_t before = allocation_failures; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && allocation_failures == before + (i == 2 ? 1u : 0u));
        finding(&out.items[0], key, false, causes[i]); br_results_clear(&out);
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
static void own_resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "fibery %s\nWork-ONE.fibery.io", key);
    const size_t sizes[] = {2 * sizeof(br_span), 45, sizeof("Work-ONE"), 44, sizeof("net/http: nil Context"), sizeof("net/http: nil Context")};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; fail_size = sizes[i]; fail_after = i == 5 ? 2 : 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1);
        rolled_back(&out, rc, error, raw, parts, cause);
    }
    for (size_t allocation = 1; allocation <= 2; ++allocation) {
        const row reply = {.key = key, .domain = "Work-ONE", .status = 500};
        script steps = {.rows = &reply, .count = 1, .arm_call = 1, .arm_size = sizeof("unexpected status code: 500"), .arm_after = allocation};
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; int rc = invoke(d, input, &steps, &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
    } /* Provider cause creation and +1 setter are fatal BEFORE ordinary results. */
    snprintf(input, sizeof(input), "fibery %s\nWork-ONE.fibery.io Other.fibery.io", key);
    const row replies[] = {{.key = key, .domain = "Work-ONE", .status = 200}, {.key = key, .domain = "Other", .status = 200}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        script steps = {.rows = replies, .count = 1};
        fail_part_after = 2; /* First result appended/verified; second finding fails before its send, including NoV/nil context. */
        int rc = mode == 0 ? invoke(d, input, &steps, &out, &error) : d->scan(d, NULL, mode == 2, text(input), &out, &error);
        CHECK(!fail_part_after); rolled_back(&out, rc, error, raw, parts, cause);
    }
    br_results out = caller_owned(); out.cap = out.len;
    unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
    script steps = {.rows = replies, .count = 2, .arm_call = 2, .arm_push = 4 * sizeof(br_result)};
    size_t before = allocation_failures; int rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
    row send_rows[] = {replies[0], {.key = key, .domain = "Other", .status = 200, .rc = 1, .send_error = "separate native transport diagnostic"}};
    steps = (script){.rows = send_rows, .count = 2, .arm_call = 2, .arm_size = sizeof("separate native transport diagnostic"), .arm_after = 1};
    out = caller_owned(); raw = out.items[0].raw.data; parts = out.items[0].secret_parts; cause = out.items[0].verification_error; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
}

int main(void)
{
    const br_detector *d = descriptor();
    keys_and_no_local_span_limit(d);
    domains(d);
    unique_products_and_statuses(d);
    retained_causes_and_redaction_order(d);
    actual_shared_setup_failures(d);
    own_resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_size);
    return test_finish("Fibery");
}
