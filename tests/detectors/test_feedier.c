/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[33], b[33]; /* Synthetic, case-distinct alphanumeric fixtures. */
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_raw_on_release;

/* Existing resource APIs only; no Authorization formatter/cap failure seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
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
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 32 && strlen(b) == 32);
    CHECK(br_feedier_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:feedier)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_feedier_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_feedier_init(&d, &error) == 0 && d && !error);
    CHECK(br_feedier_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 238 && d->version == 0 && !strcmp(d->name, "Feedier") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Feedier is a feedback management platform that allows businesses to collect and analyze customer feedback. Feedier API keys can be used to access and manage feedback data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "feedier"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 238, expected, "key"); CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 32);
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
    char input[160], changed[34];
    const char *formats[] = {"feedier '%s'", "FeEdIeR=%s", "preFEEDIERsuffix:%s", "feedier\r\n%s", "feedier\r%s", "feedier\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], a); extract_case(d, input, a);
    }
    const char *bad[] = {"%s", "%s feedier", "feed ier %s", "feedier%s", "feedier _%s", "feedier %s_", "feedier x%s", "feedier %s9"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a); extract_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "feedier%*s%s", gap, "", a); extract_case(d, input, gap == 40 ? a : NULL);
    }
    memcpy(changed, a, sizeof(a)); changed[31] = '\0';
    snprintf(input, sizeof(input), "feedier %s", changed); extract_case(d, input, NULL);
    memcpy(changed, a, sizeof(a)); changed[32] = 'Z'; changed[33] = '\0';
    snprintf(input, sizeof(input), "feedier %s", changed); extract_case(d, input, NULL);
    const char invalid[] = {'-', '_', '+'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "FEEDIER %s", changed); extract_case(d, input, NULL);
    }
    extract_case(d, "feedier aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); /* No local entropy/FP/token filter. */
    extract_case(d, "FEEDIER 00000000000000000000000000000000", "00000000000000000000000000000000");
    snprintf(input, sizeof(input), "feedier %s %s", a, b); extract_case(d, input, a); /* One prefix consumed per match. */
}

typedef struct { const char *key; int status, rc; const char *send_error, *read_error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char expected_auth[40];
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 238 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.feedier.com/v1/carriers"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[2].name, "User-Agent"));
    memcpy(s->expected_auth, "Bearer ", 7); memcpy(s->expected_auth + 7, row->key, 33);
    CHECK(strlen(request->headers[1].value) == 39 && !memcmp(request->headers[1].value, s->expected_auth, 40));
    CHECK(!strcmp(request->headers[2].value, s->suffix ? "TruffleHog feedier-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[1].value;
    static const unsigned char ignored_body[] = "\0\xffmalformed \"error\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, s->expected_auth, 40));
    s->borrowed_auth = NULL; test_http_release(user, response);
    /* Target the next finding's actual Raw allocation AFTER regex scratch and
     * the first kept occurrence, not an invented Authorization failure stage. */
    if (fail_raw_on_release) { fail_raw_on_release = false; fail_size = 32; fail_after = 1; }
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "feedier-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth); return out;
}
static void verify_one(const br_detector *d, reply row, bool verified)
{
    char input[64]; snprintf(input, sizeof(input), "feedier %s", a); row.key = a;
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == 1); result(&out.items[0], a, verified); br_results_clear(&out);
}
static void occurrences_and_constructor(const br_detector *d)
{
    char input[224]; snprintf(input, sizeof(input), "feedier %s\nFEEDIER %s\nfeedier %s\nFeedier %s\nfeedier %s", a, b, a, b, a);
    br_slice data = text(input); const char *keys[] = {a, b, a, b, a};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
    const reply rows[] = {
        {.key = a, .status = 200, .read_error = "ignored"}, {.key = b, .status = 299, .read_error = ""},
        {.key = a, .status = 403}, {.key = b, .status = 200, .rc = -7, .send_error = "cannot create Feedier result"},
        {.key = a, .status = 500, .read_error = a},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], i < 2);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 0); br_results_clear(&out); /* Constructor SKIPs. */
    out = test_scan(d, NULL, false, data.data, data.len); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}
static void verification(const br_detector *d)
{
    verify_one(d, (reply){.status = 200}, true);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verify_one(d, (reply){.status = statuses[i], .read_error = i % 2 ? "" : "cannot create Feedier result"}, statuses[i] >= 200 && statuses[i] < 300);
    char sensitive[192]; snprintf(sensitive, sizeof(sensitive), "Bearer %s repeated=%s url=https://api.feedier.com/v1/carriers", a, a);
    const char *causes[] = {"net/http: nil Context", "cannot create Feedier result", "out of memory constructing HTTP headers", sensitive, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 200, .rc = i % 2 ? -7 : 1, .send_error = causes[i], .read_error = ""}, false);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "feedier %s", a);
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
    char input[160]; snprintf(input, sizeof(input), "feedier %s\nfeedier %s\nfeedier %s", a, b, a); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 200}, {.key = b, .status = 200, .rc = 1, .send_error = "out of memory in Do"}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    for (int failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 scratch failure, even with verify off. */
        if (failure == 1) { fail_size = 33; fail_after = 2; }
        if (failure == 2) fail_raw_on_release = true;
        if (failure == 3) fail_part_after = 2; /* Positive JSON failure BEFORE second occurrence's suppressed Do. */
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create Feedier result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after && !fail_raw_on_release);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Own finding resources must fail BEFORE constructor SKIPs, too. */
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Feedier result") && !fail_part_after);
    check_prior(&out, &saved); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard after successful verification. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Feedier result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved); br_results_clear(&out);
}

int main(void)
{
    test_secret(a, 32, 0); test_secret(b, 32, 11); a[0] = 'A'; a[9] = 'Z'; a[31] = 'X'; b[20] = 'Q'; b[31] = 'Y';
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_constructor(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_raw_on_release);
    return test_finish("Feedier");
}
