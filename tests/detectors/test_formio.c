/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char jwt_header[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
static char *a, *b, *minimum, *maximum;
static size_t fail_size, fail_after, failed_allocations, fail_part_after, capture_size;
static const char *first_capture;

/* Existing resource APIs only; no trim/header-copy/format failure seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (capture_size && size == capture_size && !first_capture) first_capture = value;
    return value;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static char *token(size_t payload, size_t shift)
{
    const char alphabet[] = "b7Q9z1AbCdEfGhIjKlMnOpRsTuVwXyZ2", signature[] = "b7Q9z1_-AbCd";
    size_t size = 81 + payload; char *value = malloc(size + 1); CHECK(value);
    memcpy(value, jwt_header, 36); value[36] = '.';
    for (size_t i = 0; i < payload; ++i) value[37 + i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    value[37 + payload] = '.';
    for (size_t i = 0; i < 43; ++i) value[38 + payload + i] = signature[(i + shift) % (sizeof(signature) - 1)];
    value[size - 1] = '-'; value[size] = '\0'; return value;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(jwt_header) == 36 && strlen(minimum) == 301 && strlen(maximum) == 391 && strlen(a) == 331);
    CHECK(br_formio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:formio)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_formio_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_formio_init(&d, &error) == 0 && d && !error);
    CHECK(br_formio_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 712 && d->version == 0 && !strcmp(d->name, "FormIO") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FormIO is a platform for building form-based applications. FormIO JWT tokens can be used to authenticate and interact with FormIO services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "formio"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 712, expected, "key"); CHECK(r->raw.len >= 301 && r->raw.len <= 391 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}
typedef struct { size_t end, count; } suffix_probe;
static int consumed_suffix(void *user, const br_span *groups, size_t count)
{
    suffix_probe *probe = user; ++probe->count;
    CHECK(count == 2 && groups[0].begin == 0 && groups[0].end == probe->end + 1);
    CHECK(groups[1].begin == 7 && groups[1].end == probe->end); /* Trimmed group, required suffix STILL consumed. */
    return 0;
}
static void extraction(const br_detector *d)
{
    char input[900], changed[400];
    const char *formats[] = {"formio %s ", "FoRmIo=%s\r", "preFORMIOsuffix:%s\n", "formio\r\n%s\r\n", "formio %s  \t"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], a); extract_case(d, input, a);
    }
    const char *bad[] = {"%s ", "%s formio", "form io %s ", "formio%s ", "formio _%s ", "formio %s", "formio %s\t", "formio %s\t ", "formio %s\v"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a); extract_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "formio%*s%s\n", gap, "", a); extract_case(d, input, gap == 40 ? a : NULL);
    }
    char *short_payload = token(219, 0), *long_payload = token(311, 0);
    const char *sizes[] = {short_payload, minimum, maximum, long_payload};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(input, sizeof(input), "formio %s\n", sizes[i]); extract_case(d, input, i == 1 || i == 2 ? sizes[i] : NULL);
    }
    free(short_payload); free(long_payload);
    const size_t positions[] = {0, 120, 130, 288}; const char invalid[] = {'E', '_', '+', '+'};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, a, 332); changed[positions[i]] = invalid[i];
        snprintf(input, sizeof(input), "FORMIO %s ", changed); extract_case(d, input, NULL);
    }
    memcpy(changed, a, 332); changed[330] = '\0';
    snprintf(input, sizeof(input), "formio %s ", changed); extract_case(d, input, NULL); /* 42 signature bytes. */
    snprintf(input, sizeof(input), "formio %sA ", a); extract_case(d, input, NULL); /* 44 signature bytes. */
    snprintf(input, sizeof(input), "formio %s\r\n", a); suffix_probe probe = {.end = 7 + strlen(a)}; char *error = NULL;
    CHECK(br_regex_each(d->state, text(input), consumed_suffix, &probe, &error) == 0 && !error && probe.count == 1);
    snprintf(input, sizeof(input), "formio %s formio %s\n", a, a); br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    result(&out.items[0], a, false); result(&out.items[1], a, false); br_results_clear(&out);
}

typedef struct { const char *key; int status, rc; const char *send_error, *read_error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_token;
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 712 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://formio.form.io/current"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Jwt-Token") && !strcmp(request->headers[2].name, "User-Agent"));
    CHECK(strlen(request->headers[1].value) == strlen(row->key) && !memcmp(request->headers[1].value, row->key, strlen(row->key) + 1));
    if (http->calls == 1) CHECK(request->headers[1].value == first_capture); /* Borrow capture storage, no redundant token header copy. */
    CHECK(!strcmp(request->headers[2].value, s->suffix ? "TruffleHog formio-offline" : "TruffleHog"));
    s->borrowed_token = request->headers[1].value;
    static const unsigned char ignored_body[] = "\0\xffmalformed \"error\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; const reply *row = &s->rows[http->calls - 1];
    CHECK(s->borrowed_token && strlen(s->borrowed_token) == strlen(row->key) && !memcmp(s->borrowed_token, row->key, strlen(row->key) + 1));
    s->borrowed_token = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s, size_t token_size)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "formio-offline" : NULL}; s->ctx = &ctx;
    capture_size = token_size + 1; first_capture = NULL;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_token); capture_size = 0; first_capture = NULL; return out;
}
static void verify_one(const br_detector *d, reply row, bool verified)
{
    char input[420]; if (!row.key) row.key = a;
    snprintf(input, sizeof(input), "formio %s\n", row.key);
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s, strlen(row.key));
    CHECK(out.len == 1); result(&out.items[0], row.key, verified); br_results_clear(&out);
}
static void occurrences_and_constructor(const br_detector *d)
{
    char input[1800]; snprintf(input, sizeof(input), "formio %s formio %s\rFORMIO %s\nformio %s\r\nformio %s ", a, b, a, b, a);
    br_slice data = text(input); const char *keys[] = {a, b, a, b, a};
    script none = {0}; br_results out = run(d, data, false, &none, strlen(a)); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
    const reply rows[] = {
        {.key = a, .status = 200, .read_error = "ignored"}, {.key = b, .status = 299, .read_error = ""},
        {.key = a, .status = 401}, {.key = b, .status = 200, .rc = -7, .send_error = "cannot create FormIO result"},
        {.key = a, .status = 500, .read_error = a},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s, strlen(a)); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], i < 2);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 0); br_results_clear(&out);
    out = test_scan(d, NULL, false, data.data, data.len); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}
static void verification(const br_detector *d)
{
    verify_one(d, (reply){.key = minimum, .status = 200}, true); verify_one(d, (reply){.key = maximum, .status = 200}, true);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verify_one(d, (reply){.status = statuses[i], .read_error = i % 2 ? "" : a}, statuses[i] >= 200 && statuses[i] < 300);
    const char *causes[] = {"net/http: nil Context", "cannot create FormIO result", "out of memory constructing HTTP headers", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 200, .rc = i % 2 ? -7 : 1, .send_error = causes[i]}, false);
}
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[400]; snprintf(input, sizeof(input), "formio %s\n", a);
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode ? fail_headers : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (size_t)mode);
        CHECK(!fail_after && failed_allocations == before + (size_t)mode);
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
    char input[720]; snprintf(input, sizeof(input), "formio %s formio %s\n", a, b); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 200}, {.key = b, .status = 200, .rc = 1, .send_error = "out of memory in Do"}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    for (int failure = 0; failure < 4; ++failure) {
        capture_size = strlen(a) + 1; first_capture = NULL;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 scratch failure, verify off. */
        if (failure == 1) { fail_size = strlen(a) + 1; fail_after = 2; }
        if (failure == 2) { fail_size = strlen(a); fail_after = 2; }
        if (failure == 3) fail_part_after = 2; /* Positive finding insertion failure BEFORE suppressed Do. */
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create FormIO result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_token);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    fail_part_after = 2; /* Finding resources precede nil-context constructor SKIP. */
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FormIO result") && !fail_part_after);
    check_prior(&out, &saved); free(error); error = NULL;
    capture_size = strlen(a) + 1; first_capture = NULL; size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append FormIO result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved); br_results_clear(&out);
    capture_size = 0; first_capture = NULL;
}

int main(void)
{
    a = token(250, 0); b = token(250, 11); minimum = token(220, 3); maximum = token(310, 7);
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_constructor(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !capture_size);
    free(a); free(b); free(minimum); free(maximum); return test_finish("FormIO");
}
