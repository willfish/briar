/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[21], other[21];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 20 && strlen(other) == 20);
    CHECK(br_fxmarket_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:fxmarket)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_fxmarket_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_fxmarket_init(&d, &error) == 0 && d && !error && br_fxmarket_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 381 && d->version == 0 && !strcmp(d->name, "FXMarket") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Fxmarket is a financial market for trading currencies. Fxmarket API keys can be used to access and modify currency trading data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "fxmarket") && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}
static void check_result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 381, expected, "key"); CHECK(r->raw.len == 20 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(d, &ctx, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}
static void extraction(const br_detector *d)
{
    char input[160], changed[22];
    const char *accepted[] = {"fxmarket = '%s'", "FxMaRkEt\r\n%s", "preFXMARKETsuffix:%s", "fxmarket-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(d, input, key);
    }
    const char *rejected[] = {"%s", "%s fxmarket", "fx market %s", "fxmarket%s", "fxmarket _%s", "fxmarket %s_", "fxmarket X%s", "fxmarket %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "fxmarket%*s%s", gap, "", key); extraction_case(d, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[19] = '\0'; snprintf(input, sizeof(input), "fxmarket %s", changed); extraction_case(d, input, NULL);
    memset(changed, 'Z', 21); changed[21] = '\0'; snprintf(input, sizeof(input), "fxmarket %s", changed); extraction_case(d, input, NULL);
    memset(changed, 'Z', 20); changed[20] = '\0'; snprintf(input, sizeof(input), "fxmarket %s", changed); extraction_case(d, input, changed); /* No hex/entropy validation. */
    changed[0] = '_'; changed[19] = '_'; snprintf(input, sizeof(input), "fxmarket %s", changed); extraction_case(d, input, changed); /* '_' is a word character in source class. */
    const char invalid[] = "+/.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = invalid[i]; snprintf(input, sizeof(input), "fxmarket %s", changed); extraction_case(d, input, NULL);
    }
    snprintf(input, sizeof(input), "fxmarket %s %s", key, other); extraction_case(d, input, key);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool empty_body; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; char expected_url[61]; } script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 381 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && strlen(row->key) == 20);
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://fxmarketapi.com/apilive?api_key=%s", row->key) == 60);
    CHECK(strlen(request->url) == 60 && !memcmp(request->url, steps->expected_url, 61)); /* Original case and punctuation, no query encoding. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog fxmarket-offline"));
    steps->borrowed_url = request->url;
    static const unsigned char body[] = "\0\xff invalid JSON \"status\":401";
    http->response = (br_http_response){.status = row->status, .body = row->empty_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1}, .body_error = row->empty_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, steps->expected_url, 61));
    steps->borrowed_url = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "fxmarket-offline"}; steps->ctx = &ctx;
    br_results results = test_scan(d, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}
static void boundary_captures(const br_detector *d)
{
    char input[80], value[21], overlong[22];
    overlong[0] = 'a'; overlong[1] = '-'; memcpy(overlong + 2, other + 1, 20);
    snprintf(input, sizeof(input), "fxmarket %s", overlong); reply row = {.key = overlong + 1, .status = 200}; script steps = {.rows = &row, .count = 1};
    br_results results = run(d, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], row.key, true); br_results_clear(&results); /* Original INNER 20-byte capture from a longer token. */
    memcpy(value, other, sizeof(value)); value[19] = '='; snprintf(input, sizeof(input), "fxmarket %sq", value); row.key = value;
    results = run(d, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], value, true); br_results_clear(&results); /* Nonword '=' -> q is a boundary; '=' stays literal in query. */
    snprintf(input, sizeof(input), "fxmarket %s", value); extraction_case(d, input, NULL);
    memset(value, '-', 20); value[20] = '\0'; snprintf(input, sizeof(input), "FXMARKET%sq", value);
    results = run(d, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], value, true); br_results_clear(&results); /* Word keyword -> '-' and '-' -> q, not full-token validation. */
}
static void verification(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "fxmarket %s; FXMARKET %s; fxmarket %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .empty_body = true}, {.key = key, .status = 200, .send_rc = -7, .send_error = "cannot create FXMarket result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(d, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, verify); check_result(&results.items[1], other, verify); check_result(&results.items[2], key, false); br_results_clear(&results);
        results = test_scan(d, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 500}; snprintf(input, sizeof(input), "fxmarket %s", key);
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .empty_body = i % 2 != 0}; script steps = {.rows = &row, .count = 1}; br_results results = run(d, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_failures(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "fxmarket %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u)); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}
static void check_prior(const br_results *r, unsigned char *raw, char *cause, br_json *parts)
{
    CHECK(r->len == 1 && r->items[0].detector_type == 777 && r->items[0].verified && r->items[0].raw.data == raw && r->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(r->items[0].verification_error == cause && !strcmp(cause, "caller-owned") && r->items[0].secret_parts == parts);
}
static void own_resources(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "fxmarket %s; fxmarket %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply row = {.key = key, .status = 200}; script steps = {.rows = &row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "fxmarket-offline"}; steps.ctx = &ctx;
        fail_part_after = 2;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FXMarket result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url); check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1;
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FXMarket result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}
int main(void)
{
    test_secret(key, 20, 0); test_secret(other, 20, 11); key[0] = 'G'; key[9] = '_'; key[12] = '-'; key[17] = '='; other[3] = 'Z';
    const br_detector *d = descriptor(); extraction(d); boundary_captures(d); verification(d); shared_failures(d); own_resources(d); return test_finish("FXMarket");
}
