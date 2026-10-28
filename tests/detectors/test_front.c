/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static unsigned char key[300], other[300];
static size_t key_len, other_len;
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

#define BYTES(text) (br_slice){(const unsigned char *)(text), sizeof(text) - 1}
static br_slice token(unsigned char *out, br_slice separator, size_t suffix, size_t shift)
{
    test_secret((char *)out, 36, shift); out[0] = 'G'; out[13] = 'Z';
    memcpy(out + 36, separator.data, separator.len); test_secret((char *)out + 36 + separator.len, suffix, shift + 7);
    out[36 + separator.len + 7] = 'Y';
    return (br_slice){out, 36 + separator.len + suffix};
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && key_len == 225 && other_len == 281);
    CHECK(br_front_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:front)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_front_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_front_init(&d, &error) == 0 && d && !error && br_front_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 427 && d->version == 0 && !strcmp(d->name, "Front") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Front is a customer communication hub that allows teams to manage email, social media, SMS, and other channels in one place. Front API keys can be used to access and manage this communication data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "front") && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}

static void check_result(const br_result *r, br_slice expected, bool verified)
{
    CHECK(r->detector_type == 427 && r->raw.len == expected.len && !memcmp(r->raw.data, expected.data, expected.len));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *part = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == expected.len && !memcmp(json_object_get_string(part), expected.data, expected.len));
}

static br_results scan_token(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice value)
{
    unsigned char input[320]; CHECK(value.len + 6 <= sizeof(input)); memcpy(input, "front ", 6); memcpy(input + 6, value.data, value.len);
    return test_scan(d, ctx, verify, input, value.len + 6);
}
static void extraction_case(const br_detector *d, br_slice input, const br_slice *expected)
{
    br_results results = scan_token(d, NULL, false, input); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], *expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *d)
{
    unsigned char value[300], malformed[300]; br_slice k = {key, key_len}, maximum = {other, other_len};
    extraction_case(d, k, &k); extraction_case(d, maximum, &maximum);
    br_slice wildcard = token(value, BYTES("Q"), 188, 2); extraction_case(d, wildcard, &wildcard); /* Not a literal JWT dot or decoder. */
    wildcard = token(value, BYTES("\0"), 188, 2); extraction_case(d, wildcard, &wildcard);
    wildcard = token(value, BYTES("\r"), 188, 2); extraction_case(d, wildcard, &wildcard);
    wildcard = token(value, BYTES("\v"), 188, 2); extraction_case(d, wildcard, &wildcard);
    wildcard = token(value, BYTES("\t"), 188, 2); extraction_case(d, wildcard, &wildcard);
    wildcard = token(value, BYTES("\xf0\x9f\x9a\x80"), 244, 2); CHECK(wildcard.len == 284); extraction_case(d, wildcard, &wildcard); /* One wildcard RUNE, maximum BYTE length. */
    wildcard = token(value, BYTES("\n"), 188, 2); extraction_case(d, wildcard, NULL); /* Prefix DOTALL must not leak into capture. */
    wildcard = token(value, BYTES("!"), 187, 2); extraction_case(d, wildcard, NULL);
    memcpy(malformed, key, key_len); memmove(malformed + 35, malformed + 36, key_len - 36); extraction_case(d, (br_slice){malformed, key_len - 1}, NULL);
    memcpy(malformed, key, key_len); memmove(malformed + 37, malformed + 36, key_len - 36); malformed[36] = 'X'; extraction_case(d, (br_slice){malformed, key_len + 1}, NULL);
    wildcard = token(value, BYTES("!"), 188, 2); value[50] = '.'; value[80] = '-'; value[100] = '_'; extraction_case(d, wildcard, &wildcard);
    /* Greedy final word-boundary backtracking, NOT a full-token delimiter test. */
    wildcard = token(value, BYTES("!"), 189, 2); value[wildcard.len - 1] = '.'; br_slice shortened = {value, wildcard.len - 1}; extraction_case(d, wildcard, &shortened);
    wildcard = token(value, BYTES("!"), 244, 2); value[wildcard.len - 1] = '-'; value[wildcard.len] = 'q'; extraction_case(d, (br_slice){value, wildcard.len + 1}, &wildcard);
    wildcard = token(value, BYTES("!"), 245, 2); br_slice inner = {value + 37, 245}; extraction_case(d, wildcard, &inner); /* Overlong first candidate can yield an INNER all-word capture via source prefix backtracking. */
    unsigned char input[380]; memcpy(input, "preFRONTsuffix:", 15); memcpy(input + 15, key, key_len);
    br_results results = test_scan(d, NULL, false, input, key_len + 15); CHECK(results.len == 1); check_result(&results.items[0], k, false); br_results_clear(&results);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "FrOnT", 5); memset(input + 5, ' ', gap); memcpy(input + 5 + gap, key, key_len);
        results = test_scan(d, NULL, false, input, key_len + 5 + gap); CHECK(results.len == (gap == 40 ? 1u : 0u)); br_results_clear(&results);
    }
    memcpy(input, "front _", 7); memcpy(input + 7, key, key_len); results = test_scan(d, NULL, false, input, key_len + 7); CHECK(!results.len); br_results_clear(&results);
    results = test_scan(d, NULL, false, key, key_len); CHECK(!results.len); br_results_clear(&results);
}

typedef struct { br_slice key; int status, send_rc; bool empty_body; const char *send_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_auth; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at]; CHECK(row->key.len <= 284);
    CHECK(request->detector_type == 427 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api2.frontapp.com/accounts"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == row->key.len + 7);
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7) && !memcmp(request->headers[1].value + 7, row->key.data, row->key.len) && request->headers[1].value[row->key.len + 7] == '\0');
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog front-offline"));
    steps->borrowed_auth = request->headers[1].value;
    static const unsigned char body[] = "\0\xff invalid JSON \"status\":401";
    http->response = (br_http_response){.status = row->status, .body = row->empty_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1}, .body_error = row->empty_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; const reply *row = &steps->rows[http->calls - 1];
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, "Bearer ", 7) && !memcmp(steps->borrowed_auth + 7, row->key.data, row->key.len) && steps->borrowed_auth[row->key.len + 7] == '\0');
    steps->borrowed_auth = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, const reply *row)
{
    script steps = {.rows = row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "front-offline"}; steps.ctx = &ctx;
    br_results results = scan_token(d, &ctx, true, row->key); CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_auth); return results;
}

static void verification(const br_detector *d)
{
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = {key, key_len}, .status = statuses[i], .empty_body = i % 2 != 0}; br_results results = run(d, &row); CHECK(results.len == 1);
        check_result(&results.items[0], row.key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    unsigned char value[300]; br_slice maximum = token(value, BYTES("\xf0\x9f\x9a\x80"), 244, 2);
    reply row = {.key = maximum, .status = 200}; br_results results = run(d, &row); CHECK(results.len == 1); check_result(&results.items[0], maximum, true); br_results_clear(&results);
    row.key = token(value, BYTES("\t"), 188, 2); results = run(d, &row); CHECK(results.len == 1); check_result(&results.items[0], row.key, true); br_results_clear(&results);
    /* ABI1 NUL guard is AFTER constructor AND complete assembly, never a new
     * extraction ban, quiet drop, unsupported error or truncated-success send. */
    br_slice nul = token(value, BYTES("\0"), 188, 2); test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    results = scan_token(d, &ctx, true, nul); CHECK(results.len == 1 && !http.calls && !http.releases); check_result(&results.items[0], nul, false); br_results_clear(&results);
    results = scan_token(d, NULL, true, nul); CHECK(!results.len && !results.items && !results.cap); br_results_clear(&results);
    br_slice cr = token(value, BYTES("\r"), 188, 2); results = scan_token(d, &ctx, true, cr);
    CHECK(results.len == 1 && !http.calls && http.releases == 1); check_result(&results.items[0], cr, false); br_results_clear(&results); /* Existing whole-domain header policy, not a provider guard. */
    unsigned char input[900]; size_t at = 0; br_slice values[] = {{key, key_len}, {other, other_len}, {key, key_len}};
    for (size_t i = 0; i < 3; ++i) { memcpy(input + at, "front ", 6); at += 6; memcpy(input + at, values[i].data, values[i].len); at += values[i].len; input[at++] = ';'; }
    reply rows[] = {{.key = values[0], .status = 200}, {.key = values[1], .status = 204, .empty_body = true}, {.key = values[2], .status = 200, .send_rc = -7, .send_error = "cannot create Front result"}};
    script steps = {.rows = rows, .count = 3}; test_http scripted = {.inspect = inspect_request, .user = &steps}; br_transport injected = {&scripted, test_http_send, release_response}; br_scan_ctx injected_ctx = {.transport = &injected, .user_agent = "front-offline"}; steps.ctx = &injected_ctx;
    results = test_scan(d, &injected_ctx, true, input, at); CHECK(results.len == 3 && scripted.calls == 3 && scripted.releases == 3 && !steps.borrowed_auth);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], values[i], i < 2);
    br_results_clear(&results);
    results = test_scan(d, NULL, false, input, at); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], values[i], false);
    br_results_clear(&results);
    results = test_scan(d, NULL, true, input, at); CHECK(!results.len); br_results_clear(&results);
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0); return results;
}
static void check_prior(const br_results *r, unsigned char *raw, char *cause, br_json *parts)
{
    CHECK(r->len == 1 && r->items[0].detector_type == 777 && r->items[0].verified && r->items[0].raw.data == raw && r->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(r->items[0].verification_error == cause && !strcmp(cause, "caller-owned") && r->items[0].secret_parts == parts);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = scan_token(d, &ctx, true, (br_slice){key, key_len});
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], (br_slice){key, key_len}, false); br_results_clear(&results);
    }
    unsigned char input[650]; memcpy(input, "front ", 6); memcpy(input + 6, key, key_len); memcpy(input + 6 + key_len, ";front ", 7); memcpy(input + 13 + key_len, other, other_len); br_slice data = {input, 13 + key_len + other_len};
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply row = {.key = {key, key_len}, .status = 200}; script steps = {.rows = &row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "front-offline"}; steps.ctx = &ctx;
        char *error = NULL; fail_part_after = 2;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Front result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth); check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1;
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Front result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); error = NULL;
        /* Own finding failure must win BEFORE nil-context skip OR NUL guard. */
        unsigned char nul_key[300], nul_input[320]; br_slice nul = token(nul_key, BYTES("\0"), 188, 2); memcpy(nul_input, "front ", 6); memcpy(nul_input + 6, nul.data, nul.len); fail_part_after = 1;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, true, (br_slice){nul_input, nul.len + 6}, &results, &error) == -1 && error && !strcmp(error, "cannot create Front result") && !fail_part_after);
        check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    key_len = token(key, BYTES("!"), 188, 0).len; other_len = token(other, BYTES("."), 244, 11).len;
    const br_detector *d = descriptor(); extraction(d); verification(d); resources(d); return test_finish("Front");
}
