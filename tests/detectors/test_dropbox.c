/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char old[134], other[134], scoped[1606], long_token[5006];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static const char *fail_duplicate;
static size_t fail_duplicate_after;

/* Interpose existing resource APIs only, without production failure switches. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(text, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(text) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static void make_token(char *out, bool is_scoped, size_t size, size_t shift)
{
    size_t prefix = is_scoped ? 5 : 3;
    memcpy(out, is_scoped ? "sl.u." : "sl.", prefix); test_secret(out + prefix, size, shift);
    out[prefix + 9] = 'A'; out[prefix + 40] = '_'; out[prefix + 70] = '-'; out[prefix + size - 1] = 'Z';
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(old) == 133 && strlen(other) == 133 && strlen(scoped) == 1605 && strlen(long_token) == 5005);
    CHECK(br_dropbox_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:dropbox)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_dropbox_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_dropbox_init(&d, &error) == 0 && d && !error);
    CHECK(br_dropbox_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 18 && d->version == 0 && !strcmp(d->name, "Dropbox") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Dropbox is a file hosting service that offers cloud storage, file synchronization, personal cloud, and client software. Dropbox API keys can be used to access and manage files and folders in a Dropbox account."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "dropbox") && !strcmp(d->keywords[1], "sl."));
    CHECK(d->max_secret_size == 4096 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result(const br_result *r, const char *token, bool verified, const char *error)
{
    test_key_result(r, 18, token, "token");
    CHECK(r->verified == verified);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "token", &part));
    CHECK(json_object_get_string_len(part) == (int)strlen(token));
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[5200], changed[136];
    const char *formats[] = {"dropbox '%s'", "DrOpBoX\r\n%s", "predropboxsuffix:%s", "dropbox\r%s", "dropbox\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], old); extraction_case(d, input, old);
    }
    snprintf(input, sizeof(input), "DROPBOX %s", scoped); extraction_case(d, input, scoped);
    snprintf(input, sizeof(input), "dropbox %s", long_token); extraction_case(d, input, long_token); /* 4096 is not a local cap. */
    const char *bad[] = {"%s", "sl. %s", "%s dropbox", "drop box %s", "dropbox%s", "dropbox _%s", "dropbox x%s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], old); extraction_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dropbox%*s%s", gap, "", old); extraction_case(d, input, gap == 40 ? old : NULL);
    }
    memcpy(changed, old, sizeof(old)); changed[132] = '\0';
    snprintf(input, sizeof(input), "dropbox %s", changed); extraction_case(d, input, NULL); /* 129 body characters. */
    memcpy(changed, old, sizeof(old)); changed[0] = 'S';
    snprintf(input, sizeof(input), "dropbox %s", changed); extraction_case(d, input, NULL);
    memcpy(changed, old, sizeof(old)); changed[20] = '=';
    snprintf(input, sizeof(input), "dropbox %s", changed); extraction_case(d, input, NULL); /* No Base64 parser accepting '='. */
    snprintf(input, sizeof(input), "dropbox sl.U.%s", old + 3); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "dropbox %s---", old); extraction_case(d, input, old); /* Greedy class backtracks to a word boundary. */
    snprintf(changed, sizeof(changed), "%s_", old);
    snprintf(input, sizeof(input), "dropbox %s", changed); extraction_case(d, input, changed); /* '_' remains part of the greedy capture. */
    memcpy(changed, old, sizeof(old)); changed[3] = '-';
    snprintf(input, sizeof(input), "dropbox %s", changed); extraction_case(d, input, changed);
}

typedef struct { const char *token; int status; br_slice body; const char *read_error, *send_error; int rc; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; const char *borrowed_token;
    char read_storage[512]; size_t read_len;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 18 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.dropboxapi.com/2/users/get_current_account"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(auth && strlen(auth) == 7 + strlen(row->token) && !memcmp(auth, "Bearer ", 7));
    CHECK(!memcmp(auth + 7, row->token, strlen(row->token) + 1));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->suffix ? "TruffleHog dropbox-offline" : "TruffleHog"));
    /* Exact count excludes Type, Accept, explicit Content-Length and extras. */
    s->borrowed_auth = auth; s->borrowed_token = row->token; s->read_len = 0;
    if (row->read_error) {
        s->read_len = strlen(row->read_error); CHECK(s->read_len < sizeof(s->read_storage));
        memcpy(s->read_storage, row->read_error, s->read_len + 1);
    }
    http->response = (br_http_response){.status = row->status, .body = row->body,
        .body_error = row->read_error ? s->read_storage : NULL};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, "Bearer ", 7));
    CHECK(!strcmp(s->borrowed_auth + 7, s->borrowed_token)); s->borrowed_auth = NULL;
    /* A borrowed read cause is invalid after release. Result must own its copy. */
    memset(s->read_storage, 0xa5, s->read_len + 1);
    test_http_release(user, response);
}

static br_results run(const br_detector *d, br_slice input, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "dropbox-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, input.data, input.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth);
    return out;
}

static void unique_and_nil_context(const br_detector *d)
{
    char input[2100]; int n = snprintf(input, sizeof(input), "dropbox %s\nDROPBOX %s\ndropbox %s\ndropbox %s", old, scoped, old, other);
    CHECK(n > 0 && (size_t)n < sizeof(input)); br_slice data = {(const unsigned char *)input, (size_t)n};
    const char *tokens[] = {old, scoped, other};
    const reply rows[] = {{.token = old, .status = 200, .read_error = "ignored read error"},
        {.token = scoped, .status = 401, .body = TEXT("missing_scope")}, {.token = other, .status = 401, .body = TEXT("invalid_access_token")}};
    for (int verify = 0; verify < 2; ++verify) {
        script s = {.rows = rows, .count = verify ? 3u : 0u, .suffix = true}; br_results out = run(d, data, verify, &s);
        CHECK(out.len == 3); for (size_t i = 0; i < 3; ++i) result(&out.items[i], tokens[i], verify && i != 2, NULL);
        br_results_clear(&out);
        out = test_scan(d, NULL, verify, data.data, data.len); CHECK(out.len == 3);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], tokens[i], false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&out);
    }
    char long_input[5024]; CHECK(snprintf(long_input, sizeof(long_input), "dropbox %s", long_token) == 5013);
    reply row = {.token = long_token, .status = 200}; script s = {.rows = &row, .count = 1};
    br_results out = run(d, text(long_input), true, &s); CHECK(out.len == 1); result(&out.items[0], long_token, true, NULL); br_results_clear(&out);
}

static void verify_one(const br_detector *d, reply row, bool verified, const char *error)
{
    char input[160]; CHECK(snprintf(input, sizeof(input), "dropbox %s", old) == 141);
    row.token = old; script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == 1); result(&out.items[0], old, verified, error); br_results_clear(&out);
}

static void status_and_body_branches(const br_detector *d)
{
    const br_slice scope[] = {TEXT("\0\xffinvalid_access_token missing_scope"), TEXT("expired_access_token\0\xff" "does not have the required scope")};
    const br_slice invalid[] = {TEXT("\0\xffinvalid_access_token"), TEXT("\xff\0expired_access_token")};
    verify_one(d, (reply){.status = 200, .body = TEXT("\0\xffignored"), .read_error = "ignored"}, true, NULL);
    verify_one(d, (reply){.status = 200, .read_error = ""}, true, NULL);
    for (int status = 400; status <= 401; ++status) {
        for (size_t i = 0; i < 2; ++i) {
            verify_one(d, (reply){.status = status, .body = scope[i]}, true, NULL);
            verify_one(d, (reply){.status = status, .body = invalid[i]}, false, NULL);
        }
        verify_one(d, (reply){.status = status, .body = scope[0], .read_error = "leaf read failure"}, false, "leaf read failure");
        verify_one(d, (reply){.status = status, .body = scope[1], .read_error = ""}, false, "");
        verify_one(d, (reply){.status = status, .body = scope[0], .read_error = "failed to read response body: literal leaf"}, false, "failed to read response body: literal leaf");
        verify_one(d, (reply){.status = status, .body = TEXT("unknown\0tail")}, false, "unsupported: Dropbox non-UTF-8 or NUL response body diagnostic");
        verify_one(d, (reply){.status = status, .body = TEXT("unknown\xfftail")}, false, "unsupported: Dropbox non-UTF-8 or NUL response body diagnostic");
        char diagnostic[128]; CHECK(snprintf(diagnostic, sizeof(diagnostic), "unexpected status code: %d, body: plain \xc2\xa0\n", status) > 0);
        verify_one(d, (reply){.status = status, .body = TEXT("plain \xc2\xa0\n")}, false, diagnostic);
        CHECK(snprintf(diagnostic, sizeof(diagnostic), "unexpected status code: %d, body: ", status) > 0);
        verify_one(d, (reply){.status = status}, false, diagnostic);
    }
    const int statuses[] = {201, 204, 299, 302, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char diagnostic[64]; CHECK(snprintf(diagnostic, sizeof(diagnostic), "unexpected status code: %d", statuses[i]) > 0);
        verify_one(d, (reply){.status = statuses[i], .body = scope[0], .read_error = "ignored"}, false, diagnostic);
    }
    char read_error[256]; CHECK(snprintf(read_error, sizeof(read_error), "leaf: %s", old) > 0);
    verify_one(d, (reply){.status = 401, .body = scope[0], .read_error = read_error}, false, read_error); /* No redaction. */
    const char *causes[] = {"outer: inner: literal", "failed to read response body: not a typed wrapper", old, "unsupported: redirects for native HTTP POST", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 401, .body = scope[0], .send_error = causes[i], .rc = i % 2 ? -7 : 1}, false, causes[i] ? causes[i] : "HTTP transport failed");
}

static void full_diagnostic(const br_detector *d)
{
    unsigned char body[9000]; memset(body, 'q', sizeof(body)); memcpy(body + 8800, old, strlen(old));
    char *expected = malloc(sizeof(body) + 64); CHECK(expected);
    int n = snprintf(expected, 64, "unexpected status code: 401, body: "); CHECK(n > 0);
    memcpy(expected + n, body, sizeof(body)); expected[(size_t)n + sizeof(body)] = '\0';
    verify_one(d, (reply){.status = 401, .body = {body, sizeof(body)}}, false, expected); free(expected);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }

static void shared_send_domain(const br_detector *d)
{
    char input[160]; CHECK(snprintf(input, sizeof(input), "dropbox %s", old) == 141);
    const char *errors[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], old, false, errors[mode]); br_results_clear(&out);
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
    char input[300]; CHECK(snprintf(input, sizeof(input), "dropbox %s\ndropbox %s", old, other) == 283); br_slice data = text(input);
    const reply rows[] = {{.token = old, .status = 200}, {.token = other, .status = 200}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create Dropbox result", "cannot create Dropbox result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_size = 3 * sizeof(br_span); fail_after = 1; } /* Optional u. capture gives three groups; genuine +1 failure. */
            if (failure == 1) { fail_size = 134; fail_after = 2; }
            if (failure == 2) { fail_size = 133; fail_after = 2; }
            if (failure == 3) fail_part_after = 2; /* +1 from the second finding's part insertion. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        br_results_clear(&out);
    }
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    fail_size = 141; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot allocate Dropbox authorization") && !fail_after);
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    /* Known constructor failure retains both results WITHOUT attempting Bearer. */
    fail_size = 141; fail_after = 1; br_results nil = test_scan(d, NULL, true, data.data, data.len);
    CHECK(nil.len == 2 && fail_after == 1); fail_after = 0; br_results_clear(&nil);
    const reply diagnostic_rows[] = {rows[0], {.token = other, .status = 400, .body = TEXT("plain")}};
    s.rows = diagnostic_rows; http.calls = http.releases = 0;
    fail_size = strlen("unexpected status code: 400, body: ") + 5 + 1; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot allocate Dropbox body diagnostic") && !fail_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    const reply read_rows[] = {rows[0], {.token = other, .status = 401, .read_error = "borrowed leaf"}};
    s.rows = read_rows; http.calls = http.releases = 0; fail_duplicate = "borrowed leaf"; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dropbox verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dropbox verification error") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    s.rows = rows; http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Dropbox result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    make_token(old, false, 130, 0); make_token(other, false, 130, 11);
    make_token(scoped, true, 1600, 7); make_token(long_token, true, 5000, 19);
    const br_detector *d = descriptor();
    extraction(d); unique_and_nil_context(d); status_and_body_branches(d); full_diagnostic(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("Dropbox");
}
