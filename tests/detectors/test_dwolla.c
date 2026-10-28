/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char a[51], b[51], c[51];
static size_t fail_size, fail_after, failed_allocations, fail_part_after, basic_allocations;
static const char *fail_duplicate;
static size_t fail_duplicate_after;

/* Target existing allocation/JSON APIs, without production failure switches. */
void *malloc(size_t size)
{
    if (size == 143) ++basic_allocations;
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

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 50 && strlen(b) == 50 && strlen(c) == 50);
    CHECK(br_dwolla_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:dwolla)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_dwolla_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_dwolla_init(&d, &error) == 0 && d && !error);
    CHECK(br_dwolla_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 180 && d->version == 0 && !strcmp(d->name, "Dwolla") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Dwolla is a payment services provider that allows businesses to send, receive, and facilitate payments. Dwolla API keys can be used to access and manage these payment services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "dwolla"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void json_part(br_json *parts, const char *name, const char *expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, name, &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 50 && !memcmp(json_object_get_string(part), expected, 50));
}
static void pair_result(const br_result *r, const char *id, const char *secret, bool verified, const char *error)
{
    CHECK(r->detector_type == 180 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == 50 && !memcmp(r->raw.data, id, 50));
    CHECK(r->raw_v2.len == 100 && !memcmp(r->raw_v2.data, id, 50) && !memcmp(r->raw_v2.data + 50, secret, 50));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    json_part(r->secret_parts, "id", id); json_part(r->secret_parts, "secret", secret);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = basic_allocations; br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 2u : 0u) && !http.calls && !http.releases && basic_allocations == before);
    if (expected) { pair_result(&out.items[0], expected, b, false, NULL); pair_result(&out.items[1], b, expected, false, NULL); }
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[1700], changed[52];
    const char *formats[] = {"dwolla '%s'\nDWOLLA %s", "predwollasuffix:%s\ndwolla %s", "DwOlLa\r\n%s\ndwolla %s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], a, b); extraction_case(d, input, a);
    }
    const char *bad[] = {"%s\ndwolla %s", "dwolla%s\ndwolla %s", "dwolla _%s\ndwolla %s", "dwolla %s_\ndwolla %s", "dwolla x%s\ndwolla %s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a, b); extraction_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dwolla%*s%s\ndwolla %s", gap, "", a, b); extraction_case(d, input, gap == 40 ? a : NULL);
    }
    memcpy(changed, a, sizeof(a)); changed[49] = '\0';
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, NULL);
    memcpy(changed, a, sizeof(a)); changed[50] = 'A'; changed[51] = '\0';
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, NULL);
    const char invalid[] = {'_', '+', '.', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, NULL);
    }
    memcpy(changed, a, sizeof(a)); changed[0] = '-';
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "dwolla%s\ndwolla %s", changed, b); extraction_case(d, input, changed); /* Source leading-nonword boundary quirk. */
    memcpy(changed, a, sizeof(a)); changed[49] = '-';
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "dwolla %sX\ndwolla %s", changed, b); extraction_case(d, input, changed); /* Fixed capture ends nonword before outside word. */
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s\ndwolla %s", a, a, a); extraction_case(d, input, NULL); /* Equal directed pairs are skipped. */
    int n = snprintf(input, sizeof(input), "dwolla %s", a); CHECK(n == 57);
    memset(input + n, ' ', 1300); snprintf(input + n + 1300, sizeof(input) - (size_t)n - 1300, "\ndwolla %s", b);
    extraction_case(d, input, a); /* No local 1024-byte span constraint. */
}

typedef struct { const char *id, *secret; int status, rc; const char *error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth, *borrowed_id, *borrowed_secret; br_slice borrowed_body;
    char *returned_error;
} script;

static void check_basic(const char *auth, const char *id, const char *secret)
{
    CHECK(auth && strlen(auth) == 142 && !memcmp(auth, "Basic ", 6));
    CHECK(auth[141] == '=' && auth[140] != '=');
    unsigned char decoded[104]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 136) == 102);
    CHECK(!memcmp(decoded, id, 50) && decoded[50] == ':' && !memcmp(decoded + 51, secret, 50));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 180 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api-sandbox.dwolla.com/token"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization")); check_basic(request->headers[1].value, row->id, row->secret);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, s->suffix ? "TruffleHog dwolla-offline" : "TruffleHog"));
    CHECK(request->body.data && request->body.len == 29 && !memcmp(request->body.data, "grant_type=client_credentials", 29));
    /* Exact header count excludes Accept and invented logical Content-Length. */
    s->borrowed_auth = request->headers[1].value; s->borrowed_id = row->id; s->borrowed_secret = row->secret; s->borrowed_body = request->body;
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
    check_basic(s->borrowed_auth, s->borrowed_id, s->borrowed_secret); s->borrowed_auth = NULL;
    CHECK(s->borrowed_body.len == 29 && !memcmp(s->borrowed_body.data, "grant_type=client_credentials", 29)); s->borrowed_body = (br_slice){0};
    /* Result must already own its redacted copy before transport release. */
    if (s->returned_error) memset(s->returned_error, '!', strlen(s->returned_error));
    s->returned_error = NULL;
    test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "dwolla-offline" : NULL}; s->ctx = &ctx;
    size_t before = basic_allocations; br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth && !s->borrowed_body.data);
    CHECK(basic_allocations == before + s->count); return out;
}

static void products_and_no_break(const br_detector *d)
{
    char input[256]; CHECK(snprintf(input, sizeof(input), "dwolla %s\nDWOLLA %s\ndwolla %s\ndwolla %s", a, b, a, c) == 231); br_slice data = text(input);
    const char *values[] = {a, b, c}; reply rows[6]; size_t at = 0;
    const int statuses[] = {200, 401, 503, 200, 201, 200};
    for (size_t i = 0; i < 3; ++i) for (size_t s = 0; s < 3; ++s) if (i != s) {
        rows[at] = (reply){values[i], values[s], statuses[at], 0, NULL}; ++at;
    }
    CHECK(at == 6);
    for (int verify = 0; verify < 2; ++verify) {
        script s = {.rows = rows, .count = verify ? 6u : 0u, .suffix = true}; br_results out = run(d, data, verify, &s); CHECK(out.len == 6);
        for (size_t i = 0; i < 6; ++i) {
            char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected status code %d", rows[i].status) > 0);
            pair_result(&out.items[i], rows[i].id, rows[i].secret, verify && rows[i].status == 200,
                !verify || rows[i].status == 200 || rows[i].status == 401 ? NULL : error);
        }
        CHECK(out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
        size_t before = basic_allocations; out = test_scan(d, NULL, verify, data.data, data.len);
        CHECK(out.len == 6 && basic_allocations == before + (verify ? 6u : 0u));
        for (size_t i = 0; i < 6; ++i) pair_result(&out.items[i], rows[i].id, rows[i].secret, false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&out);
    }
    char changed[51]; memcpy(changed, a, sizeof(a)); changed[0] = 'a';
    snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", changed, b); extraction_case(d, input, changed);
}

static void verification(const br_detector *d)
{
    char input[128]; CHECK(snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", a, b) == 115); br_slice data = text(input);
    const int statuses[] = {200, 401, 201, 204, 299, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        const reply rows[] = {{a, b, statuses[i], 0, NULL}, {b, a, statuses[i], 0, NULL}}; script s = {.rows = rows, .count = 2};
        br_results out = run(d, data, true, &s); CHECK(out.len == 2);
        char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected status code %d", statuses[i]) > 0);
        for (size_t r = 0; r < 2; ++r) pair_result(&out.items[r], rows[r].id, rows[r].secret, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : error);
        br_results_clear(&out);
    }
    char cause[256]; CHECK(snprintf(cause, sizeof(cause), "outer: %s / %s / %s / %s", a, b, a, b) > 0);
    const char *causes[] = {cause, "outer: inner: literal", "net/http: nil Context", "unsupported: redirects for native HTTP POST", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        const reply rows[] = {{a, b, 200, i % 2 ? -7 : 1, causes[i]}, {b, a, 200, 1, causes[i]}}; script s = {.rows = rows, .count = 2};
        br_results out = run(d, data, true, &s); CHECK(out.len == 2);
        const char *expected = i == 0 ? "outer: [REDACTED] / [REDACTED] / [REDACTED] / [REDACTED]" : causes[i] ? causes[i] : "HTTP transport failed";
        for (size_t r = 0; r < 2; ++r) pair_result(&out.items[r], rows[r].id, rows[r].secret, false, expected);
        br_results_clear(&out);
    }
    /* ID-first replacement is observable when the two 50-byte values overlap. */
    char left[51], right[51], overlap[52]; memset(left, 'A', 50); left[50] = '\0';
    memcpy(right, left, sizeof(left)); right[49] = 'B'; memcpy(overlap, left, 50); overlap[50] = 'B'; overlap[51] = '\0';
    CHECK(snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", left, right) == 115);
    const reply rows[] = {{left, right, 200, 1, overlap}, {right, left, 200, 1, overlap}}; script s = {.rows = rows, .count = 2};
    br_results out = run(d, text(input), true, &s); CHECK(out.len == 2);
    pair_result(&out.items[0], left, right, false, "[REDACTED]B"); pair_result(&out.items[1], right, left, false, "A[REDACTED]"); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[128]; CHECK(snprintf(input, sizeof(input), "dwolla %s\ndwolla %s", a, b) == 115);
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
    char input[192]; CHECK(snprintf(input, sizeof(input), "dwolla %s\ndwolla %s\ndwolla %s", a, b, c) == 173); br_slice data = text(input);
    reply rows[] = {{a, b, 200, 0, NULL}, {a, c, 200, 0, NULL}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create Dwolla result", "cannot create Dwolla result", "cannot create Dwolla result"};
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 capture failure. */
            if (failure == 1) { fail_size = 51; fail_after = 2; }
            if (failure == 2) { fail_size = 50; fail_after = 2; }
            if (failure == 3) { fail_size = 100; fail_after = 2; } /* RawV2, no separator. */
            if (failure == 4) fail_part_after = 4; /* +1 adding the second pair's secret. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        br_results_clear(&out);
    }
    for (int nil = 0; nil < 2; ++nil) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        fail_size = 143; fail_after = 2; size_t before = basic_allocations;
        CHECK(d->scan(d, nil ? NULL : &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
        CHECK(basic_allocations == before + 2 && http.calls == (nil ? 0u : 1u) && http.releases == http.calls);
        check_prior(&out, &saved); free(error); br_results_clear(&out);
    }
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    rows[1].status = 503; script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    fail_duplicate = "unexpected status code 503"; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dwolla verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2; size_t before = basic_allocations;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dwolla verification error") && !fail_duplicate_after);
    CHECK(basic_allocations == before + 2); check_prior(&out, &saved); free(error); error = NULL;
    http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Dwolla result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    test_secret(a, 50, 0); test_secret(b, 50, 11); test_secret(c, 50, 19);
    a[0] = 'A'; a[13] = '-'; a[49] = 'Z'; b[8] = 'Q'; b[22] = '-'; c[11] = 'G'; c[32] = '-';
    const br_detector *d = descriptor();
    extraction(d); products_and_no_break(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("Dwolla");
}
