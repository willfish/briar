/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[22], b[22], c[22];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static const char *fail_duplicate;
static size_t fail_duplicate_after;

/* Exercise existing allocation/JSON APIs, without payload-format failure seams. */
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
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 21 && strlen(b) == 21 && strlen(c) == 21);
    CHECK(br_endorlabs_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_endorlabs_init(&d, &error) == 0 && d && !error);
    CHECK(br_endorlabs_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 993 && d->version == 0 && !strcmp(d->name, "EndorLabs") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Endorlabs provides API keys that can be used to authenticate and interact with its services. These keys should be kept confidential to prevent unauthorized access."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "endr+"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void json_part(br_json *parts, const char *name, const char *expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, name, &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 21 && !memcmp(json_object_get_string(part), expected, 21));
}
static void pair_result(const br_result *r, const char *key, const char *secret, bool verified, const char *error)
{
    CHECK(r->detector_type == 993 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == 21 && !memcmp(r->raw.data, key, 21));
    CHECK(r->raw_v2.len == 42 && !memcmp(r->raw_v2.data, key, 21) && !memcmp(r->raw_v2.data + 21, secret, 21));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    json_part(r->secret_parts, "key", key); json_part(r->secret_parts, "secret", secret);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 2u : 0u) && !http.calls && !http.releases);
    if (expected) { pair_result(&out.items[0], expected, b, false, NULL); pair_result(&out.items[1], b, expected, false, NULL); }
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[1600], changed[23];
    snprintf(input, sizeof(input), "%s\n%s", a, b); extract_case(d, input, a); /* Direct, no provider-name prefix needed. */
    snprintf(input, sizeof(input), "'%s'\r\n%s", a, b); extract_case(d, input, a);
    const char *bad[] = {"x%s\n%s", "_%s\n%s", "%s_\n%s", "%s9\n%s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a, b); extract_case(d, input, NULL);
    }
    memcpy(changed, a, sizeof(a)); changed[0] = 'E';
    snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    memcpy(changed, a, sizeof(a)); changed[4] = '-';
    snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    memcpy(changed, a, sizeof(a)); changed[20] = '\0';
    snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    memcpy(changed, a, sizeof(a)); changed[21] = 'A'; changed[22] = '\0';
    snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    const char invalid[] = {'_', '/', '='};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    }
    snprintf(input, sizeof(input), "%s---\n%s", a, b); extract_case(d, input, a); /* Boundary before appended nonword hyphens. */
    memcpy(changed, a, sizeof(a)); changed[20] = '-';
    snprintf(input, sizeof(input), "%s\n%s", changed, b); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "%sX\n%s", changed, b); extract_case(d, input, changed); /* Capture can end nonword before outside word. */
    memcpy(changed, "endr+", 5); memset(changed + 5, '-', 16); changed[21] = '\0';
    snprintf(input, sizeof(input), "%sX\n%s", changed, b); extract_case(d, input, changed); /* No alnum-tail/entropy validator. */
    snprintf(input, sizeof(input), "%s\n%s\n%s", a, a, a); extract_case(d, input, NULL); /* Unique set/equal-pair skip. */
    int n = snprintf(input, sizeof(input), "%s", a); CHECK(n == 21);
    memset(input + n, ' ', 1300); snprintf(input + n + 1300, sizeof(input) - (size_t)n - 1300, "\n%s", b);
    extract_case(d, input, a); /* No scanner-local credential-span limit. */
}

typedef struct { const char *key, *secret; int status, rc; const char *error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    br_slice borrowed_body; char expected_body[66]; char *returned_error;
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 993 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.endorlabs.com/v1/auth/api-key"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->suffix ? "TruffleHog endorlabs-offline" : "TruffleHog"));
    CHECK(snprintf(s->expected_body, sizeof(s->expected_body), "{\"key\":\"%s\", \"secret\":\"%s\"}", row->key, row->secret) == 65);
    CHECK(request->body.data && request->body.len == 65 && !memcmp(request->body.data, s->expected_body, 66));
    /* Exact field order/comma-space/NUL lifetime; no escaping, newline, Auth,
     * Accept, dedup key or invented logical Content-Length. No live auth call. */
    s->borrowed_body = request->body;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)}, .body_error = "ignored read/drain error"};
    http->send_rc = row->rc; http->send_error = row->error;
}
static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *s = http->user; s->returned_error = *error;
    return rc;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_body.data && s->borrowed_body.len == 65 && !memcmp(s->borrowed_body.data, s->expected_body, 66));
    s->borrowed_body = (br_slice){0};
    /* Findings must own their ordered-redacted cause before release. */
    if (s->returned_error) memset(s->returned_error, '!', strlen(s->returned_error));
    s->returned_error = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "endorlabs-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_body.data); return out;
}

static void products_and_no_break(const br_detector *d)
{
    char input[128]; CHECK(snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", a, b, a, c) == 87); br_slice data = text(input);
    const char *values[] = {a, b, c}; const int statuses[] = {200, 200, 401, 503, 201, 200}; reply rows[6]; size_t at = 0;
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) if (k != s) {
        rows[at] = (reply){values[k], values[s], statuses[at], 0, NULL}; ++at;
    }
    CHECK(at == 6);
    for (int verify = 0; verify < 2; ++verify) {
        script s = {.rows = rows, .count = verify ? 6u : 0u, .suffix = true}; br_results out = run(d, data, verify, &s); CHECK(out.len == 6);
        for (size_t i = 0; i < 6; ++i) {
            char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected HTTP response status %d", rows[i].status) > 0);
            pair_result(&out.items[i], rows[i].key, rows[i].secret, verify && rows[i].status == 200,
                !verify || rows[i].status == 200 || rows[i].status == 401 ? NULL : error);
        }
        CHECK(out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
        out = test_scan(d, NULL, verify, data.data, data.len); CHECK(out.len == 6);
        for (size_t i = 0; i < 6; ++i) pair_result(&out.items[i], rows[i].key, rows[i].secret, false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&out);
    }
    /* Tail case remains part of the original identity, not a lowercased set. */
    char changed[22]; memcpy(changed, a, sizeof(a)); changed[5] = 'a';
    CHECK(snprintf(input, sizeof(input), "%s\n%s", a, changed) == 43);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    pair_result(&out.items[0], a, changed, false, NULL); pair_result(&out.items[1], changed, a, false, NULL); br_results_clear(&out);
}

static void verification(const br_detector *d)
{
    char input[64]; CHECK(snprintf(input, sizeof(input), "%s\n%s", a, b) == 43); br_slice data = text(input);
    const int statuses[] = {200, 401, 201, 204, 299, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        const reply rows[] = {{a, b, statuses[i], 0, NULL}, {b, a, statuses[i], 0, NULL}}; script s = {.rows = rows, .count = 2};
        br_results out = run(d, data, true, &s); CHECK(out.len == 2);
        char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]) > 0);
        for (size_t r = 0; r < 2; ++r) pair_result(&out.items[r], rows[r].key, rows[r].secret, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : error);
        br_results_clear(&out);
    }
    char echo[128]; CHECK(snprintf(echo, sizeof(echo), "outer: %s %s %s %s", a, b, a, b) > 0);
    const char *causes[] = {echo, "outer: inner: literal", "net/http: nil Context", "unsupported: redirects for native HTTP POST", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        const reply rows[] = {{a, b, 200, i % 2 ? -7 : 1, causes[i]}, {b, a, 200, 1, causes[i]}}; script s = {.rows = rows, .count = 2};
        br_results out = run(d, data, true, &s); CHECK(out.len == 2);
        const char *expected = i == 0 ? "outer: [REDACTED] [REDACTED] [REDACTED] [REDACTED]" : causes[i] ? causes[i] : "HTTP transport failed";
        for (size_t r = 0; r < 2; ++r) pair_result(&out.items[r], rows[r].key, rows[r].secret, false, expected);
        br_results_clear(&out);
    }
    /* Valid source tokens can overlap across a trailing 'endr' and next '+'. */
    const char left[] = "endr+AAAAAAAAAAAAendr", right[] = "endr+BBBBBBBBBBBBBBBB";
    char overlap[39]; CHECK(snprintf(overlap, sizeof(overlap), "%s+BBBBBBBBBBBBBBBB", left) == 38);
    CHECK(snprintf(input, sizeof(input), "%s\n%s", left, right) == 43);
    const reply rows[] = {{left, right, 200, 1, overlap}, {right, left, 200, 1, overlap}}; script s = {.rows = rows, .count = 2};
    br_results out = run(d, text(input), true, &s); CHECK(out.len == 2);
    pair_result(&out.items[0], left, right, false, "[REDACTED]+BBBBBBBBBBBBBBBB");
    pair_result(&out.items[1], right, left, false, "endr+AAAAAAAAAAAA[REDACTED]"); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[64]; CHECK(snprintf(input, sizeof(input), "%s\n%s", a, b) == 43);
    const char *errors[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 2 && !http.calls && http.releases == (mode == 0 ? 0u : 2u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 2u : 0u));
        pair_result(&out.items[0], a, b, false, errors[mode]); pair_result(&out.items[1], b, a, false, errors[mode]); br_results_clear(&out);
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
    char input[80]; CHECK(snprintf(input, sizeof(input), "%s\n%s\n%s", a, b, c) == 65); br_slice data = text(input);
    reply rows[] = {{a, b, 200, 0, NULL}, {a, c, 200, 0, NULL}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create EndorLabs result", "cannot create EndorLabs result", "cannot create EndorLabs result"};
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 capture failure. */
            if (failure == 1) { fail_size = 22; fail_after = 2; }
            if (failure == 2) { fail_size = 21; fail_after = 2; }
            if (failure == 3) { fail_size = 42; fail_after = 2; } /* RawV2, no separator. */
            if (failure == 4) fail_part_after = 4; /* +1 adding the second finding's secret. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_body.data);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        br_results_clear(&out);
    }
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    rows[1].status = 503; script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    fail_duplicate = "unexpected HTTP response status 503"; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set EndorLabs verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set EndorLabs verification error") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append EndorLabs result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    memcpy(a, "endr+", 5); memcpy(b, "endr+", 5); memcpy(c, "endr+", 5);
    test_secret(a + 5, 16, 0); test_secret(b + 5, 16, 7); test_secret(c + 5, 16, 19);
    a[5] = 'A'; a[11] = '-'; a[20] = 'Z'; b[9] = 'Q'; c[13] = 'G';
    const br_detector *d = descriptor();
    extraction(d); products_and_no_break(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("EndorLabs");
}
