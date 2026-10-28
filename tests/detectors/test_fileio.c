/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[40], b[40]; /* Synthetic uppercase/digit/dot/hyphen fixtures. */
static const char huge_integer[] = "99999999999999999999" "99999999999999999999" "99999999999999999999" "99999999999999999999";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate;

/* Exercise existing allocation/JSON APIs, not Authorization format seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(value, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 39 && strlen(b) == 39);
    CHECK(br_fileio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:fileio)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_fileio_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_fileio_init(&d, &error) == 0 && d && !error);
    CHECK(br_fileio_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 527 && d->version == 0 && !strcmp(d->name, "FileIO") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FileIO is a service for temporary file sharing. The detected key can be used to access and manage shared files."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "fileio"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 527, expected, "key"); CHECK(r->raw.len == 39 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 39);
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[192], changed[41];
    const char *formats[] = {"fileio '%s'", "FiLeIo=%s", "preFILEIOsuffix:%s", "fileio\r\n%s", "fileio\r%s", "fileio\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], a); extract_case(d, input, a);
    }
    const char *bad[] = {"%s", "%s fileio", "file.io %s", "file io %s", "fileio%s", "fileio _%s", "fileio %s_", "fileio x%s", "fileio %s9"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a); extract_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "fileio%*s%s", gap, "", a); extract_case(d, input, gap == 40 ? a : NULL);
    }
    memcpy(changed, a, sizeof(a)); changed[38] = '\0';
    snprintf(input, sizeof(input), "fileio %s", changed); extract_case(d, input, NULL);
    const char invalid[] = {'a', 'z', '_', '+', '/'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[17] = invalid[i];
        snprintf(input, sizeof(input), "FILEIO %s", changed); extract_case(d, input, NULL);
    }
    /* Boundary behavior is NOT full-token validation: longer class-runs can
     * leave punctuation outside the capture, or include it next to word bytes. */
    snprintf(input, sizeof(input), "fileio .%s", a); extract_case(d, input, a);
    snprintf(input, sizeof(input), "fileio %s-", a); extract_case(d, input, a);
    memcpy(changed, a, sizeof(a)); changed[0] = '.';
    snprintf(input, sizeof(input), "fileio %s", changed); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "fileio x%s", changed); extract_case(d, input, changed);
    memcpy(changed, a, sizeof(a)); changed[38] = '-';
    snprintf(input, sizeof(input), "fileio %s", changed); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "fileio %sx", changed); extract_case(d, input, changed);
    memset(changed, '-', 39); changed[39] = '\0';
    snprintf(input, sizeof(input), "fileio x%sx", changed); extract_case(d, input, changed);
    memset(changed, '0', 39); changed[39] = '\0';
    snprintf(input, sizeof(input), "fileio %s", changed); extract_case(d, input, changed); /* No local entropy/FP filter. */
    snprintf(input, sizeof(input), "fileio %s %s", a, b); extract_case(d, input, a);
}

typedef struct {
    const char *key; int status; br_slice body; const char *read_error, *send_error; int rc;
    const char *fail_cause; bool fail_shadow;
} reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char expected_auth[47];
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 527 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://file.io/"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[1].name, "User-Agent"));
    memcpy(s->expected_auth, "Bearer ", 7); memcpy(s->expected_auth + 7, row->key, 40);
    CHECK(strlen(request->headers[0].value) == 46 && !memcmp(request->headers[0].value, s->expected_auth, 47));
    CHECK(!strcmp(request->headers[1].value, s->suffix ? "TruffleHog fileio-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[0].value;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
    if (row->fail_cause) { fail_duplicate = row->fail_cause; fail_duplicate_after = 1; }
    if (row->fail_shadow) { fail_size = row->body.len + 1; fail_after = 1; }
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, s->expected_auth, 47));
    s->borrowed_auth = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "fileio-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth); return out;
}
static void verify_one(const br_detector *d, reply row, bool verified)
{
    char input[64]; snprintf(input, sizeof(input), "fileio %s", a); row.key = a;
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == 1); result(&out.items[0], a, verified); br_results_clear(&out);
}
static void occurrences_and_constructor(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "fileio %s\nFILEIO %s\nfileio %s\nFileio %s\nfileio %s", a, b, a, b, a);
    br_slice data = text(input); const char *keys[] = {a, b, a, b, a};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
    const reply rows[] = {
        {.key = a, .status = 201, .body = TEXT("null")},
        {.key = b, .status = 200, .body = TEXT("{}"), .read_error = ""},
        {.key = a, .status = 200, .body = TEXT("{} {}")},
        {.key = b, .status = 200, .body = TEXT("true"), .rc = -7, .send_error = "cannot validate FileIO response JSON"},
        {.key = a, .status = 299, .body = TEXT("1e9999")},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], i == 0 || i == 4);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 0); br_results_clear(&out);
    out = test_scan(d, NULL, false, data.data, data.len); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}
static void json_and_read_order(const br_detector *d)
{
    const br_slice valid[] = {TEXT("{}"), TEXT("[]"), TEXT("null"), TEXT("true"), TEXT("false"), TEXT("\"scalar\""), TEXT("123"), TEXT("-0.25e+3"), TEXT("\r\n [null,true,{}]\t"), TEXT("1e9999"), TEXT(huge_integer), TEXT("{\"n\":1e9999}")};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
        verify_one(d, (reply){.status = 200, .body = valid[i]}, true);
    const br_slice invalid[] = {{0}, TEXT("{"), TEXT("{} {}"), TEXT("true false"), TEXT("{}garbage"), TEXT("{}\0")};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        verify_one(d, (reply){.status = 200, .body = invalid[i]}, false);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        verify_one(d, (reply){.status = statuses[i], .body = TEXT("null")}, statuses[i] >= 200 && statuses[i] < 300);
        verify_one(d, (reply){.status = statuses[i], .body = TEXT("{}"), .read_error = i % 2 ? "" : "synthetic read failure"}, false);
    }
    /* A non-NULL Reader error must PREVENT validation, not merely force false. */
    verify_one(d, (reply){.status = 200, .body = TEXT("{"), .read_error = "", .fail_cause = "unexpected EOF"}, false);
    CHECK(fail_duplicate_after == 1); fail_duplicate_after = 0;
    verify_one(d, (reply){.status = 401, .body = TEXT("{"), .read_error = "synthetic read failure", .fail_cause = "unexpected EOF"}, false);
    CHECK(fail_duplicate_after == 1); fail_duplicate_after = 0;
    char sensitive[192]; snprintf(sensitive, sizeof(sensitive), "Bearer %s repeated=%s url=https://file.io/", a, a);
    const char *causes[] = {"net/http: nil Context", "cannot create FileIO result", "cannot validate FileIO response JSON", "out of memory constructing HTTP headers", sensitive, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 200, .body = TEXT("{"), .send_error = causes[i], .rc = i % 2 ? -7 : 1, .fail_cause = "unexpected EOF"}, false);
    CHECK(fail_duplicate_after == 1); fail_duplicate_after = 0;
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "fileio %s", a);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], a, false); br_results_clear(&out);
    }
}
static void prior_result(br_results *out)
{
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].secret_parts == prior->secret_parts && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}
static void resource_failures(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "fileio %s\nfileio %s", a, b); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 200, .body = TEXT("{}")}, {.key = b, .status = 200, .body = TEXT("null"), .rc = 1, .send_error = "out of memory in Do"}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    for (int failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 scratch failure, verify off. */
        if (failure == 1) { fail_size = 40; fail_after = 2; }
        if (failure == 2) { fail_size = 39; fail_after = 2; }
        if (failure == 3) fail_part_after = 2; /* Positive finding JSON failure BEFORE suppressed Do. */
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create FileIO result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FileIO result") && !fail_part_after);
    check_prior(&out, &saved); free(error); error = NULL;
    /* Whole-document helper/cause resource failures MUST precede rejection
     * statuses and ordinary-invalid-JSON suppression, rolling back earlier OK. */
    const char *causes[] = {"unexpected EOF", "unexpected end of JSON input"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        rows[1] = (reply){.key = b, .status = 401, .body = TEXT("{"), .fail_cause = causes[i]};
        CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot validate FileIO response JSON") && !fail_duplicate_after);
        CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    rows[1] = (reply){.key = b, .status = 403, .body = TEXT(huge_integer), .fail_shadow = true};
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot validate FileIO response JSON") && !fail_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard after successful verification. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append FileIO result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved); br_results_clear(&out);
}

int main(void)
{
    test_secret(a, 39, 0); test_secret(b, 39, 11);
    for (size_t i = 0; i < 39; ++i) {
        if (a[i] >= 'a' && a[i] <= 'z') a[i] -= 'a' - 'A';
        if (b[i] >= 'a' && b[i] <= 'z') b[i] -= 'a' - 'A';
    }
    a[0] = 'A'; a[9] = '.'; a[20] = '-'; a[38] = 'Z'; b[3] = '-'; b[21] = '.'; b[38] = 'Y';
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_constructor(d); json_and_read_order(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("FileIO");
}
