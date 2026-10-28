/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Synthetic fixtures only, never accepted from credentials or the environment. */
static const char key[] = "c7e2b8f0a6d4e9b1c3f5a7d0", other[] = "d3a8e1c0f9b5d7a2e6c4b8f0";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static const char *fail_duplicate, *watch_duplicate;
static size_t fail_duplicate_after, watched_attempts, watched_copies;

/* Exercise existing resource APIs, not Bearer/URL formatter failure seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    bool watched = watch_duplicate && !strcmp(value, watch_duplicate);
    if (watched) ++watched_attempts;
    if (fail_duplicate_after && fail_duplicate && !strcmp(value, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) { memcpy(copy, value, size); if (watched) ++watched_copies; }
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 24 && strlen(other) == 24);
    CHECK(br_exchangerateapi_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:exchangerate|exchange-rate)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_exchangerateapi_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_exchangerateapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_exchangerateapi_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 360 && d->version == 0 && !strcmp(d->name, "ExchangeRateAPI") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "An API key for determining the exchange rate of currencies"));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "exchangerate") && !strcmp(d->keywords[1], "exchange-rate"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified, const char *error)
{
    test_key_result(r, 360, expected, "key"); CHECK(r->raw.len == 24 && r->verified == verified);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 24);
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[160], changed[26];
    const char *formats[] = {"exchangerate '%s'", "exchange-rate=%s", "ExChAnGeRaTe %s", "EXCHANGE-RATE %s", "preEXCHANGE-RATEsuffix:%s", "exchangerate\r\n%s", "exchange-rate\r%s", "exchangerate\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); extract_case(d, input, key);
    }
    const char *bad[] = {"%s", "%s exchangerate", "exchange rate %s", "exchange_rate %s", "exchangerate%s", "exchange-rate _%s", "exchangerate %s_", "exchangerate x%s", "exchange-rate %sf"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "exchange-rate%*s%s", gap, "", key); extract_case(d, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[23] = '\0';
    snprintf(input, sizeof(input), "exchangerate %s", changed); extract_case(d, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[24] = 'a'; changed[25] = '\0';
    snprintf(input, sizeof(input), "exchange-rate %s", changed); extract_case(d, input, NULL);
    const char invalid[] = {'A', 'F', 'g', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "EXCHANGERATE %s", changed); extract_case(d, input, NULL);
    }
    extract_case(d, "exchange-rate 000000000000000000000000", "000000000000000000000000");
    extract_case(d, "exchangerate abcdefabcdefabcdefabcdef", "abcdefabcdefabcdefabcdef"); /* No randomness/FP/token filtering. */
    snprintf(input, sizeof(input), "exchangerate %s %s", key, other); extract_case(d, input, key); /* One consumed prefix per match. */
}

typedef struct {
    const char *key; int status, rc; const char *send_error, *read_error, *error;
    bool verified, setter_fails;
} reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char expected_auth[32];
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 360 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://v6.exchangerate-api.com/v6/latest/USD"));
    CHECK(!strstr(request->url, row->key)); /* Do not repair the source's keyless URL. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[1].name, "User-Agent"));
    memcpy(s->expected_auth, "Bearer ", 7); memcpy(s->expected_auth + 7, row->key, 25);
    CHECK(strlen(request->headers[0].value) == 31 && !memcmp(request->headers[0].value, s->expected_auth, 32));
    CHECK(!strcmp(request->headers[1].value, s->suffix ? "TruffleHog exchangerate-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[0].value;
    watch_duplicate = row->error; watched_attempts = watched_copies = 0;
    static const unsigned char ignored_body[] = "\0\xff{broken \"OK\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; const reply *row = &s->rows[http->calls - 1];
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, s->expected_auth, 32));
    /* Retained status causes are actually copied by the shared setter BEFORE
     * release; no artificial provider setter or format implementation. */
    CHECK(watched_attempts == (row->error ? 1u : 0u));
    CHECK(watched_copies == (row->error && !row->setter_fails ? 1u : 0u));
    watch_duplicate = NULL; s->borrowed_auth = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "exchangerate-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth && !watch_duplicate); return out;
}
static void verify_one(const br_detector *d, reply row)
{
    char input[64]; snprintf(input, sizeof(input), "exchange-rate %s", key);
    row.key = key; script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == 1); result(&out.items[0], key, row.verified, row.error); br_results_clear(&out);
}
static void occurrences_and_constructor(const br_detector *d)
{
    char input[224]; snprintf(input, sizeof(input), "exchangerate %s\nEXCHANGE-RATE %s\nexchange-rate %s\nexchangerate %s\nExChAnGeRaTe %s", key, other, key, other, key);
    br_slice data = text(input); const char *keys[] = {key, other, key, other, key};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false, NULL);
    br_results_clear(&out);
    const reply rows[] = {
        {.key = key, .status = 200, .read_error = "ignored", .verified = true},
        {.key = other, .status = 403, .read_error = ""},
        {.key = key, .status = 401, .rc = 1, .send_error = "unexpected status code: 401"},
        {.key = other, .status = 401, .read_error = key, .error = "unexpected status code: 401"},
        {.key = key, .status = 200, .verified = true},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], rows[i].verified, rows[i].error);
    br_results_clear(&out);
    for (int verify = 0; verify < 2; ++verify) {
        out = test_scan(d, NULL, verify, data.data, data.len); CHECK(out.len == 5);
        for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&out);
    }
}
static void verification(const br_detector *d)
{
    const reply rows[] = {
        {.status = 200, .verified = true}, {.status = 200, .read_error = "", .verified = true}, {.status = 200, .read_error = key, .verified = true},
        {.status = 403}, {.status = 403, .read_error = ""}, {.status = 403, .read_error = key},
        {.status = 201, .read_error = key, .error = "unexpected status code: 201"},
        {.status = 204, .error = "unexpected status code: 204"},
        {.status = 302, .read_error = "", .error = "unexpected status code: 302"},
        {.status = 401, .read_error = "net/http: nil Context", .error = "unexpected status code: 401"},
        {.status = 429, .error = "unexpected status code: 429"},
        {.status = 500, .read_error = key, .error = "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) verify_one(d, rows[i]);
    char sensitive[224]; snprintf(sensitive, sizeof(sensitive), "Bearer %s repeated=%s other=%s url=https://v6.exchangerate-api.com/v6/latest/USD", key, key, other);
    const char *causes[] = {"out of memory constructing HTTP headers", "cannot create ExchangeRateAPI result", "net/http: nil Context", "unexpected status code: 401", sensitive, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = i % 2 ? 200 : 401, .rc = i % 2 ? -7 : 1, .send_error = causes[i], .read_error = key});
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "exchangerate %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], key, false, NULL); br_results_clear(&out);
    }
}
static void token_setter_contract(void)
{
    /* Retained source causes contain no token. Independently exercise the
     * shared token-only redaction/NULL contract used by both provider sites. */
    br_result r = {0}; br_slice secret = text(key); char cause[224], expected[224];
    snprintf(cause, sizeof(cause), "Bearer %s repeated=%s other=%s url=https://v6.exchangerate-api.com/v6/latest/USD", key, key, other);
    snprintf(expected, sizeof(expected), "Bearer [REDACTED] repeated=[REDACTED] other=%s url=https://v6.exchangerate-api.com/v6/latest/USD", other);
    CHECK(br_result_set_verification_error(&r, cause, &secret, 1) == 0 && r.verification_error && !strcmp(r.verification_error, expected));
    char *owned = r.verification_error;
    CHECK(br_result_set_verification_error(&r, NULL, &secret, 1) == 0 && r.verification_error == owned);
    fail_duplicate = "unexpected status code: 401"; fail_duplicate_after = 1;
    CHECK(br_result_set_verification_error(&r, fail_duplicate, &secret, 1) == 1 && !fail_duplicate_after && r.verification_error == owned);
    br_result_clear(&r);
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
    char input[96]; snprintf(input, sizeof(input), "exchangerate %s\nexchange-rate %s", key, other); br_slice data = text(input);
    reply rows[] = {{.key = key, .status = 200, .verified = true}, {.key = other, .status = 403}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create ExchangeRateAPI result", "cannot create ExchangeRateAPI result"};
    for (int failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 capture failure, even with verification off. */
        if (failure == 1) { fail_size = 25; fail_after = 2; }
        if (failure == 2) { fail_size = 24; fail_after = 2; }
        if (failure == 3) { fail_part_after = 2; rows[1].rc = 1; rows[1].send_error = "out of memory in Do"; }
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Finding allocation precedes even nil-context error retention. */
    fail_size = 24; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create ExchangeRateAPI result") && !fail_after);
    check_prior(&out, &saved); free(error); error = NULL;
    rows[1] = (reply){.key = other, .status = 401, .error = "unexpected status code: 401", .setter_fails = true};
    fail_duplicate = rows[1].error; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set ExchangeRateAPI verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_auth); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set ExchangeRateAPI verification error") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append ExchangeRateAPI result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_constructor(d); verification(d); shared_send_domain(d); token_setter_contract(); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after && !watch_duplicate);
    return test_finish("ExchangeRateAPI");
}
