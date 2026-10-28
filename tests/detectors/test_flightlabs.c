/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
static const char url_prefix[] = "https://www.goflightlabs.com/airports-by-filter?access_key=", url_suffix[] = "&iata_code=JFK";
static char *a, *b, *minimum, *large;
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate, *watch_duplicate, *last_url;
static size_t watched_copies, url_size, url_attempts;

/* Track the REAL complete URL allocation, without formatting/cap seams or
 * another URL copy. Native allocation/JSON failures exercise owned resources. */
void *malloc(size_t size)
{
    bool url = url_size && size == url_size;
    if (url) { ++url_attempts; last_url = NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (url) last_url = value;
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
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static char *token(size_t payload, size_t shift)
{
    const char alphabet[] = "abcXYZ012_-";
    size_t size = 126 + payload; char *value = malloc(size + 1); CHECK(value);
    memcpy(value, header, 36); memcpy(value + 36, ".ey", 3);
    for (size_t i = 0; i < payload; ++i) value[39 + i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    value[39 + payload] = '.';
    for (size_t i = 0; i < 86; ++i) value[40 + payload + i] = alphabet[(i + shift + 3) % (sizeof(alphabet) - 1)];
    value[size - 1] = 'Z'; value[size] = '\0'; return value;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(header) == 36 && strlen(minimum) == 127 && strlen(a) == 129 && strlen(b) == 129);
    CHECK(br_flightlabs_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_flightlabs_init(&d, &error) == 0 && d && !error);
    CHECK(br_flightlabs_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 848 && d->version == 0 && !strcmp(d->name, "FlightLabs") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FlightLabs provides a comprehensive API for accessing real-time and historical flight data. The API keys can be used to query flight information, schedules, and other related data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], header));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified, const char *cause)
{
    test_key_result(r, 848, expected, "key"); CHECK(r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    size_t before = url_attempts; br_results out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && url_attempts == before);
    if (expected) result(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[512], changed[130]; extract_case(d, minimum, minimum); extract_case(d, a, a);
    snprintf(input, sizeof(input), "'%s'", a); extract_case(d, input, a);
    snprintf(input, sizeof(input), "x%s", a); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "_%s", a); extract_case(d, input, NULL);
    snprintf(input, sizeof(input), "%sx", a); extract_case(d, input, NULL); /* 87 word signature bytes are NOT 86. */
    snprintf(input, sizeof(input), "%s-", a); extract_case(d, input, a); /* No full-token validation. */
    memcpy(changed, a, 130); changed[128] = '-'; extract_case(d, changed, NULL);
    snprintf(input, sizeof(input), "%sx", changed); extract_case(d, input, changed); /* Boundary nonword -> word. */
    memcpy(changed, a, 130); changed[0] = 'E'; extract_case(d, changed, NULL);
    memcpy(changed, a, 130); changed[38] = 'Y'; extract_case(d, changed, NULL); /* Literal .ey is case-sensitive too. */
    memcpy(changed, a, 130); changed[40] = '!'; extract_case(d, changed, NULL);
    memcpy(changed, a, 130); changed[90] = '+'; extract_case(d, changed, NULL);
    memcpy(changed, a, 130); changed[128] = '\0'; extract_case(d, changed, NULL);
    char *empty_payload = token(0, 0); extract_case(d, empty_payload, NULL); free(empty_payload);
    extract_case(d, header, NULL);
    extract_case(d, large, large); /* No JWT/Base64/claims validation or payload cap. */
}

typedef struct {
    const char *key; int status, rc; const char *send_error, *read_error, *cause;
    bool verified, copy_fails, fail_redaction;
} reply;
typedef struct {
    const reply *rows; size_t count, url_start; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url; char *transport_storage;
} script;
static void check_url(const char *url, const char *key)
{
    size_t size = strlen(key);
    CHECK(sizeof(url_prefix) - 1 + sizeof(url_suffix) == 74);
    CHECK(strlen(url) == size + 73 && !memcmp(url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(url + sizeof(url_prefix) - 1, key, size));
    CHECK(!memcmp(url + sizeof(url_prefix) - 1 + size, url_suffix, sizeof(url_suffix)));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(url_attempts == s->url_start + http->calls && request->url == last_url);
    CHECK(request->detector_type == 848 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, row->key);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, s->suffix ? "TruffleHog flightlabs-offline" : "TruffleHog"));
    s->borrowed_url = request->url;
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
    watch_duplicate = row->send_error ? row->send_error : row->cause; watched_copies = 0;
    return rc;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; const reply *row = &s->rows[http->calls - 1];
    CHECK(s->borrowed_url && s->borrowed_url == last_url); check_url(s->borrowed_url, row->key);
    size_t expected = row->cause && !row->copy_fails ? 1u : 0u;
    if (row->rc && !row->send_error) ++expected; /* Shared fallback allocation, then setter copy. */
    CHECK(watched_copies == expected); watch_duplicate = NULL;
    /* Poison the borrowed original cause: provider results must ALREADY own
     * the token-redacted copy before release, including failure paths. */
    if (s->transport_storage) memset(s->transport_storage, '!', strlen(s->transport_storage));
    s->transport_storage = NULL; s->borrowed_url = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s, size_t token_size)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "flightlabs-offline" : NULL}; s->ctx = &ctx;
    s->url_start = url_attempts; url_size = token_size + 74;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url && !watch_duplicate);
    CHECK(url_attempts == s->url_start + (verify ? s->count : 0)); url_size = 0; last_url = NULL; return out;
}
static void verify_one(const br_detector *d, reply row)
{
    if (!row.key) row.key = a;
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(row.key), true, &s, strlen(row.key));
    CHECK(out.len == 1); result(&out.items[0], row.key, row.verified, row.cause); br_results_clear(&out);
}
static void unique_and_unbounded(const br_detector *d)
{
    char input[560]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", a, b, a, b); br_slice data = text(input);
    script none = {0}; br_results out = run(d, data, false, &none, strlen(a)); CHECK(out.len == 2);
    result(&out.items[0], a, false, NULL); result(&out.items[1], b, false, NULL); br_results_clear(&out);
    const reply rows[] = {{.key = a, .status = 200, .verified = true, .read_error = a}, {.key = b, .status = 401}};
    script s = {.rows = rows, .count = 2, .suffix = true}; out = run(d, data, true, &s, strlen(a)); CHECK(out.len == 2);
    result(&out.items[0], a, true, NULL); result(&out.items[1], b, false, NULL); br_results_clear(&out);
    size_t before = url_attempts; url_size = strlen(a) + 74;
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 2 && url_attempts == before + 2);
    result(&out.items[0], a, false, "net/http: nil Context"); result(&out.items[1], b, false, "net/http: nil Context");
    url_size = 0; last_url = NULL; br_results_clear(&out);
    verify_one(d, (reply){.key = minimum, .status = 200, .verified = true});
    verify_one(d, (reply){.key = large, .status = 200, .verified = true, .read_error = ""}); /* 65,537 payload bytes, not a bounded JWT field. */
}
static void verification_and_redaction(const br_detector *d)
{
    const reply rows[] = {{.status = 200, .verified = true}, {.status = 401, .read_error = a},
        {.status = 201, .cause = "unexpected status code: 201", .read_error = ""},
        {.status = 403, .cause = "unexpected status code: 403"}, {.status = 500, .cause = "unexpected status code: 500"},
        {.status = 200, .rc = 1, .send_error = "cannot allocate FlightLabs URL", .cause = "cannot allocate FlightLabs URL"},
        {.status = 200, .rc = -7, .send_error = "out of memory constructing HTTP headers", .cause = "out of memory constructing HTTP headers"},
        {.rc = 1, .send_error = "", .cause = ""}, {.rc = 1, .cause = "HTTP transport failed"}};
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) verify_one(d, rows[i]);
    char sensitive[520], redacted[280];
    snprintf(sensitive, sizeof(sensitive), "key=%s repeated=%s other=%s header=%s", a, a, b, header);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] repeated=[REDACTED] other=%s header=%s", b, header);
    verify_one(d, (reply){.status = 200, .rc = -1, .send_error = sensitive, .cause = redacted});
}
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static void shared_send_causes(const br_detector *d)
{
    const char *causes[] = {"HTTP transport not installed", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode ? fail_headers : NULL};
        size_t before = failed_allocations, urls = url_attempts; url_size = strlen(a) + 74;
        br_results out = test_scan(d, &ctx, true, a, strlen(a));
        CHECK(out.len == 1 && !http.calls && http.releases == (size_t)mode && url_attempts == urls + 1);
        CHECK(!fail_after && failed_allocations == before + (size_t)mode);
        url_size = 0; last_url = NULL; result(&out.items[0], a, false, causes[mode]); br_results_clear(&out);
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
    char input[280]; snprintf(input, sizeof(input), "%s\n%s", a, b); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 200}, {.key = b, .status = 401}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    url_size = strlen(a) + 74;
    for (int failure = 0; failure < 5; ++failure) {
        s.url_start = url_attempts;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 scratch failure, verify off. */
        if (failure == 1) { fail_size = strlen(a) + 1; fail_after = 2; }
        if (failure == 2) { fail_size = strlen(a); fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        if (failure == 4) { fail_size = url_size; fail_after = 2; }
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : failure == 4 ? "cannot allocate FlightLabs URL" : "cannot create FlightLabs result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_url);
        CHECK(url_attempts == s.url_start + (failure == 4 ? 2u : failure >= 2 ? 1u : 0u));
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* The complete URL is required BEFORE nil-context handling, not skipped or
     * deferred. Its second allocation failure must roll back the first result. */
    s.url_start = url_attempts; fail_size = url_size; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot allocate FlightLabs URL") && !fail_after);
    CHECK(url_attempts == s.url_start + 2); check_prior(&out, &saved); free(error); error = NULL;
    s.url_start = url_attempts; fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FlightLabs result") && !fail_part_after);
    CHECK(url_attempts == s.url_start + 1); check_prior(&out, &saved); free(error); error = NULL;
    rows[1] = (reply){.key = b, .status = 503, .cause = "unexpected status code: 503", .copy_fails = true};
    fail_duplicate = rows[1].cause; fail_duplicate_after = 1; s.url_start = url_attempts;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set FlightLabs verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2 && url_attempts == s.url_start + 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    rows[1] = (reply){.key = b, .status = 200, .rc = 1, .send_error = b, .cause = "[REDACTED]", .fail_redaction = true};
    s.url_start = url_attempts;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set FlightLabs verification error") && !fail_after);
    CHECK(http.calls == 2 && http.releases == 2 && url_attempts == s.url_start + 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2; s.url_start = url_attempts;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set FlightLabs verification error") && !fail_duplicate_after);
    CHECK(url_attempts == s.url_start + 2); check_prior(&out, &saved); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; s.url_start = url_attempts; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append FlightLabs result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1 && url_attempts == s.url_start + 1); check_prior(&out, &saved);
    free(error); br_results_clear(&out); url_size = 0; last_url = NULL;
}

int main(void)
{
    minimum = token(1, 0); a = token(3, 0); b = token(3, 5); large = token(65537, 7);
    const br_detector *d = descriptor();
    extraction(d); unique_and_unbounded(d); verification_and_redaction(d); shared_send_causes(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after && !watch_duplicate && !url_size);
    free(minimum); free(a); free(b); free(large);
    return test_finish("FlightLabs");
}
