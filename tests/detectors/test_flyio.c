/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char *a, *b, *large;
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate, *watch_duplicate, *last_auth;
static size_t watched_copies, auth_size, auth_attempts;

/* Real complete Authorization allocations, with no formatter/cap seams or
 * redundant copy. Other faults target existing native resource APIs. */
void *malloc(size_t size)
{
    bool auth = auth_size && size == auth_size;
    if (auth) { ++auth_attempts; last_auth = NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (auth) last_auth = value;
    return value;
}
char *strdup(const char *value)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(value, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) { memcpy(copy, value, size); if (watch_duplicate && !strcmp(value, watch_duplicate)) ++watched_copies; }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static char *token(size_t digits, size_t payload, bool punctuated)
{
    const char alphabet[] = "bQ8zR2+/_=,-";
    size_t size = 9 + digits + payload; char *value = malloc(size + 1); CHECK(value);
    memcpy(value, "FlyV1 fm", 8);
    for (size_t i = 0; i < digits; ++i) value[8 + i] = "1234567890"[i % 10];
    value[8 + digits] = '_';
    for (size_t i = 0; i < payload; ++i) value[9 + digits + i] = punctuated ? alphabet[i % (sizeof(alphabet) - 1)] : 'Q';
    if (payload && punctuated) value[size - 1] = 'Z';
    value[size] = '\0'; return value;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 513 && strlen(b) == 513);
    CHECK(br_flyio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_flyio_init(&d, &error) == 0 && d && !error);
    CHECK(br_flyio_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 980 && d->version == 0 && !strcmp(d->name, "FlyIO") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Fly.io is a platform for running applications globally. Fly.io tokens can be used to access the Fly.io API and manage applications."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "FlyV1"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && d->false_positive && !d->clean && !d->clean_always && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified, const char *cause)
{
    test_key_result(r, 980, expected, "key"); CHECK(r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    size_t before = auth_attempts; br_results out = test_scan(d, NULL, false, input, strlen(input));
    if (out.len != (expected ? 1u : 0u) || auth_attempts != before)
        fprintf(stderr, "extraction lengths: input=%zu expected=%zu count=%zu captured=%zu\n", strlen(input), expected ? strlen(expected) : 0, out.len, out.len ? out.items[0].raw.len : 0);
    CHECK(out.len == (expected ? 1u : 0u) && auth_attempts == before);
    if (expected) result(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[1500], changed[514]; extract_case(d, a, a);
    snprintf(input, sizeof(input), "'%s'", a); extract_case(d, input, a);
    snprintf(input, sizeof(input), "x%s", a); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "_%s", a); extract_case(d, input, NULL);
    const size_t positions[] = {0, 5, 6, 8, 260}; const char replacements[] = {'f', '\t', 'F', 'A', '!'};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, a, 514); changed[positions[i]] = replacements[i]; extract_case(d, changed, NULL);
    }
    memcpy(changed, a, 514); changed[8] = (char)0xd9; changed[9] = (char)0xa1; extract_case(d, changed, NULL); /* Arabic digit is NOT ASCII \d. */
    char *no_digits = token(0, 501, true); extract_case(d, no_digits, NULL); free(no_digits);
    char *short_payload = token(1, 499, false), *minimum = token(1, 500, false), *maximum = token(1, 700, false), *too_long = token(1, 701, false);
    extract_case(d, short_payload, NULL); extract_case(d, minimum, minimum); extract_case(d, maximum, maximum); extract_case(d, too_long, NULL);
    snprintf(input, sizeof(input), "%s=", minimum); extract_case(d, input, minimum); /* Greedy payload backtracks before nonword '='. */
    snprintf(input, sizeof(input), "%s-", maximum); extract_case(d, input, maximum); /* No EOF/full-token assertion. */
    char *backtracked = token(1, 699, false);
    maximum[strlen(maximum) - 1] = '-'; extract_case(d, maximum, backtracked); /* Backtracks from 700 to 699 before '-'. */
    snprintf(input, sizeof(input), "%sx", maximum); extract_case(d, input, maximum); /* Boundary can be nonword -> word at 700. */
    minimum[strlen(minimum) - 1] = '-'; extract_case(d, minimum, NULL); /* Cannot backtrack below 500. */
    free(backtracked); free(short_payload); free(minimum); free(maximum); free(too_long);
    extract_case(d, large, large); /* Digit run, unlike payload, is unbounded. */
}
static bool hook(const br_detector *d, br_slice raw, char **reason)
{
    br_result r = {.raw = {(unsigned char *)raw.data, raw.len}};
    return d->false_positive(d, &r, reason);
}
static void false_positive_hook(const br_detector *d)
{
    char *reason = (char *)"stale";
    CHECK(!hook(d, TEXT("AAAAAAexample"), &reason) && !reason);
    CHECK(!hook(d, TEXT("example\0\xff" "AAAAAA"), &reason) && !reason); /* Binary search BEFORE UTF8 validation or NUL truncation. */
    CHECK(hook(d, TEXT("example\0\xff" "aaaaaa"), &reason) && reason && !strcmp(reason, "invalid utf8")); free(reason); reason = NULL;
    CHECK(hook(d, TEXT("AAAAAa"), &reason) && reason && !strcmp(reason, "matches term: aaaaaa")); free(reason); reason = NULL;
    const char *terms[] = {"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"};
    for (size_t i = 0; i < 7; ++i) {
        char expected[64]; snprintf(expected, sizeof(expected), "matches term: %s", terms[i]);
        CHECK(hook(d, text(terms[i]), &reason) && reason && !strcmp(reason, expected)); free(reason); reason = NULL;
    }
    CHECK(hook(d, TEXT("password"), &reason) && reason && !strncmp(reason, "matches wordlist: ", 18)); free(reason); reason = NULL;
    CHECK(!hook(d, TEXT(""), &reason) && !reason);
    fail_size = 1; fail_after = 1;
    CHECK(!hook(d, TEXT("AAAAAAexample"), &reason) && !reason && fail_after == 1); fail_after = 0; /* No empty-reason allocation. */
    fail_size = 4; fail_after = 1;
    CHECK(hook(d, TEXT("zz9"), &reason) && reason && !strcmp(reason, "unsupported: false-positive allocation failed") && !fail_after);
    free(reason); reason = NULL; /* Existing helper remains fail closed; do not turn unsupported into false. */
    char *candidate = strdup(a); CHECK(candidate); memcpy(candidate + 12, "AAAAAAexample", 13);
    br_results out = test_scan(d, NULL, false, candidate, strlen(candidate)); CHECK(out.len == 1);
    CHECK(!d->false_positive(d, &out.items[0], &reason) && !reason); br_results_clear(&out);
    memcpy(candidate + 12, "BBBBBB", 6); out = test_scan(d, NULL, false, candidate, strlen(candidate)); CHECK(out.len == 1); /* No in-scan filtering. */
    CHECK(d->false_positive(d, &out.items[0], &reason) && reason && !strcmp(reason, "contains term: example"));
    free(reason); br_results_clear(&out); free(candidate);
}

typedef struct {
    const char *key; int status, rc; const char *send_error, *read_error, *cause;
    bool verified, copy_fails, fail_redaction;
} reply;
typedef struct {
    const reply *rows; size_t count, auth_start; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char *transport_storage;
} script;
static void check_auth(const char *value, const char *key)
{
    CHECK(strlen(value) == strlen(key) + 7 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, key, strlen(key) + 1));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(auth_attempts == s->auth_start + http->calls && request->headers[1].value == last_auth);
    CHECK(request->detector_type == 980 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.machines.dev/v1/apps?org_slug="));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[2].name, "User-Agent")); check_auth(request->headers[1].value, row->key);
    CHECK(!strcmp(request->headers[2].value, s->suffix ? "TruffleHog flyio-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[1].value;
    static const unsigned char ignored_body[] = "\0\xffmalformed \"error\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
    if (row->fail_redaction) { fail_size = sizeof("[REDACTED]"); fail_after = 1; }
}
static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    test_http *http = user; script *s = http->user;
    int rc = test_http_send(user, ctx, request, response, error);
    const reply *row = &s->rows[http->calls - 1]; s->transport_storage = *error;
    watch_duplicate = row->send_error ? row->send_error : row->cause; watched_copies = 0; return rc;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; const reply *row = &s->rows[http->calls - 1];
    CHECK(s->borrowed_auth && s->borrowed_auth == last_auth); check_auth(s->borrowed_auth, row->key);
    size_t expected = row->cause && !row->copy_fails ? 1u : 0u;
    if (row->rc && !row->send_error) ++expected;
    CHECK(watched_copies == expected); watch_duplicate = NULL;
    /* Provider-owned cause must ALREADY have been copied/redacted. */
    if (s->transport_storage) memset(s->transport_storage, '!', strlen(s->transport_storage));
    s->transport_storage = NULL; s->borrowed_auth = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s, size_t token_size)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "flyio-offline" : NULL}; s->ctx = &ctx;
    s->auth_start = auth_attempts; auth_size = token_size + 8;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth && !watch_duplicate);
    CHECK(auth_attempts == s->auth_start + (verify ? s->count : 0)); auth_size = 0; last_auth = NULL; return out;
}
static void verify_one(const br_detector *d, reply row)
{
    if (!row.key) row.key = a;
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(row.key), true, &s, strlen(row.key));
    CHECK(out.len == 1); result(&out.items[0], row.key, row.verified, row.cause); br_results_clear(&out);
}
static void unique_and_constructor(const br_detector *d)
{
    char input[2200]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", a, b, a, b); br_slice data = text(input);
    script none = {0}; br_results out = run(d, data, false, &none, strlen(a)); CHECK(out.len == 2);
    result(&out.items[0], a, false, NULL); result(&out.items[1], b, false, NULL); br_results_clear(&out);
    const reply rows[] = {{.key = a, .status = 400, .verified = true, .read_error = ""}, {.key = b, .status = 401}};
    script s = {.rows = rows, .count = 2, .suffix = true}; out = run(d, data, true, &s, strlen(a)); CHECK(out.len == 2);
    result(&out.items[0], a, true, NULL); result(&out.items[1], b, false, NULL); br_results_clear(&out);
    size_t before = auth_attempts; auth_size = strlen(a) + 8; fail_size = auth_size; fail_after = 1;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 1;
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 2 && auth_attempts == before && fail_after == 1 && fail_duplicate_after == 1);
    fail_after = fail_duplicate_after = 0; auth_size = 0; last_auth = NULL;
    result(&out.items[0], a, false, NULL); result(&out.items[1], b, false, NULL); br_results_clear(&out);
    verify_one(d, (reply){.key = large, .status = 400, .verified = true, .read_error = large}); /* Digit run is 65,537 bytes. */
}
static void verification_and_redaction(const br_detector *d)
{
    const reply rows[] = {{.status = 400, .verified = true}, {.status = 401, .read_error = a},
        {.status = 200, .cause = "unexpected HTTP response status 200", .read_error = ""},
        {.status = 403, .cause = "unexpected HTTP response status 403"}, {.status = 500, .cause = "unexpected HTTP response status 500"},
        {.status = 400, .rc = 1, .send_error = "cannot allocate FlyIO Authorization", .cause = "cannot allocate FlyIO Authorization"},
        {.status = 400, .rc = -7, .send_error = "out of memory constructing HTTP headers", .cause = "out of memory constructing HTTP headers"},
        {.rc = 1, .send_error = "", .cause = ""}, {.rc = 1, .cause = "HTTP transport failed"}};
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) verify_one(d, rows[i]);
    char sensitive[1800], redacted[700];
    snprintf(sensitive, sizeof(sensitive), "key=%s Bearer %s other=%s", a, a, b);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] Bearer [REDACTED] other=%s", b);
    verify_one(d, (reply){.status = 400, .rc = -1, .send_error = sensitive, .cause = redacted});
}
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_causes(const br_detector *d)
{
    const char *causes[] = {"HTTP transport not installed", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode ? fail_headers : NULL};
        size_t before = failed_allocations, attempts = auth_attempts; auth_size = strlen(a) + 8;
        br_results out = test_scan(d, &ctx, true, a, strlen(a));
        CHECK(out.len == 1 && !http.calls && http.releases == (size_t)mode && auth_attempts == attempts + 1);
        CHECK(!fail_after && failed_allocations == before + (size_t)mode);
        auth_size = 0; last_auth = NULL; result(&out.items[0], a, false, causes[mode]); br_results_clear(&out);
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
    char input[1100]; snprintf(input, sizeof(input), "%s\n%s", a, b); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 400}, {.key = b, .status = 401}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL; auth_size = strlen(a) + 8;
    for (int failure = 0; failure < 5; ++failure) {
        s.auth_start = auth_attempts;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 scratch failure, verify off. */
        if (failure == 1) { fail_size = strlen(a) + 1; fail_after = 2; }
        if (failure == 2) { fail_size = strlen(a); fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        if (failure == 4) { fail_size = auth_size; fail_after = 2; }
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : failure == 4 ? "cannot allocate FlyIO Authorization" : "cannot create FlyIO result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
        CHECK(auth_attempts == s.auth_start + (failure == 4 ? 2u : failure >= 2 ? 1u : 0u));
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    s.auth_start = auth_attempts; fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FlyIO result") && !fail_part_after);
    CHECK(auth_attempts == s.auth_start); check_prior(&out, &saved); free(error); error = NULL;
    rows[1] = (reply){.key = b, .status = 503, .cause = "unexpected HTTP response status 503", .copy_fails = true};
    fail_duplicate = rows[1].cause; fail_duplicate_after = 1; s.auth_start = auth_attempts;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set FlyIO verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2 && auth_attempts == s.auth_start + 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    rows[1] = (reply){.key = b, .status = 400, .rc = 1, .send_error = b, .cause = "[REDACTED]", .fail_redaction = true};
    s.auth_start = auth_attempts;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set FlyIO verification error") && !fail_after);
    CHECK(http.calls == 2 && http.releases == 2 && auth_attempts == s.auth_start + 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    size_t cap = out.cap; out.cap = 0; s.auth_start = auth_attempts; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append FlyIO result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1 && auth_attempts == s.auth_start + 1); check_prior(&out, &saved);
    free(error); br_results_clear(&out); auth_size = 0; last_auth = NULL;
}

int main(void)
{
    a = token(3, 501, true); b = token(3, 501, true); b[12] = 'B'; large = token(65537, 500, true);
    const br_detector *d = descriptor();
    extraction(d); false_positive_hook(d); unique_and_constructor(d); verification_and_redaction(d); shared_send_causes(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after && !watch_duplicate && !auth_size);
    free(a); free(b); free(large); return test_finish("FlyIO");
}
