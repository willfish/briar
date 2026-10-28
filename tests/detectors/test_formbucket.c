/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static size_t fail_size, fail_after, allocation_failures, fail_part_after;
static unsigned auth_arm;
static bool watch_auth;
static size_t auth_size, auth_calls;
static void *auth_pointer;

void *malloc(size_t size)
{
    bool auth = watch_auth && size == auth_size;
    if (auth) ++auth_calls;
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    void *out = calloc(1, size);
    if (auth) auth_pointer = out;
    return out;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && auth_arm && !strcmp(name, "key")) {
        watch_auth = true; fail_size = auth_size; fail_after = auth_arm == 2 ? 1 : auth_arm == 3 ? 2 : 0; auth_arm = 0;
    }
    return rc;
}

static void probe_auth(size_t len, unsigned mode)
{
    watch_auth = false; auth_pointer = NULL; auth_calls = 0; auth_size = len + 8; auth_arm = mode; fail_after = 0;
}
static void stop_probe(void) { watch_auth = false; auth_arm = 0; fail_after = 0; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && br_formbucket_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:formbucket)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_formbucket_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_formbucket_init(&d, &error) == 0 && d && !error && br_formbucket_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 713 && d->version == 0 && !strcmp(d->name, "FormBucket") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FormBucket is a service used to collect and manage form submissions. The detected credential can be used to access and modify form data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "formbucket"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, br_slice expected, bool verified)
{
    CHECK(r->detector_type == 713 && r->raw.len == expected.len && !memcmp(r->raw.data, expected.data, expected.len));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *part = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == expected.len && !memcmp(json_object_get_string(part), expected.data, expected.len));
}

#define BYTES(text) (br_slice){(const unsigned char *)(text), sizeof(text) - 1}
static br_results scan_token(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice key)
{
    char *input = malloc(key.len + 12); CHECK(input); memcpy(input, "formbucket ", 11); memcpy(input + 11, key.data, key.len); input[key.len + 11] = '\0';
    br_results results = test_scan(d, ctx, verify, input, key.len + 11); free(input); return results;
}

static void extraction_case(const br_detector *d, br_slice key, bool accepted)
{
    br_results results = scan_token(d, NULL, false, key); CHECK(results.len == (accepted ? 1u : 0u));
    if (accepted) check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *d)
{
    extraction_case(d, BYTES("A.B.C"), true);
    extraction_case(d, BYTES("A!B.C_-"), true); /* No end boundary; not JWT/Base64 validation. */
    extraction_case(d, BYTES("ABC.DEF"), true); /* Wildcard may itself be alphanumeric after backtracking. */
    extraction_case(d, BYTES("A B.C"), true);
    extraction_case(d, BYTES("A\rB.C"), true); extraction_case(d, BYTES("A\vB.C"), true); extraction_case(d, BYTES("A\tB.C"), true);
    extraction_case(d, BYTES("A\0B.C"), true); extraction_case(d, BYTES("A\xc3\xa9" "B.C"), true); /* Wildcard is ONE rune, not one byte. */
    extraction_case(d, BYTES("A\nB.C"), false); /* Prefix is DOTALL; this source separator is NOT. */
    extraction_case(d, BYTES("_A.B.C"), false); extraction_case(d, BYTES("A..C"), false);
    br_results results = test_scan(d, NULL, false, "FoRmBuCkEt A.B.C_-=tail", sizeof("FoRmBuCkEt A.B.C_-=tail") - 1); CHECK(results.len == 1);
    check_result(&results.items[0], BYTES("A.B.C_-"), false); br_results_clear(&results);
    results = test_scan(d, NULL, false, "preFORMBUCKETsuffix:A.B.C", sizeof("preFORMBUCKETsuffix:A.B.C") - 1); CHECK(results.len == 1);
    check_result(&results.items[0], BYTES("A.B.C"), false); br_results_clear(&results);
    char input[80];
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "formbucket%*sA.B.C", gap, ""); results = test_scan(d, NULL, false, input, strlen(input)); CHECK(results.len == (gap == 40 ? 1u : 0u)); br_results_clear(&results);
    }
}

typedef struct { br_slice key, body; const char *read_error, *send_error; int status, send_rc; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_auth; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 713 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.formbucket.com/v1/profile"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == row->key.len + 7);
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7) && !memcmp(request->headers[1].value + 7, row->key.data, row->key.len) && request->headers[1].value[row->key.len + 7] == '\0');
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog formbucket-offline"));
    steps->borrowed_auth = request->headers[1].value; CHECK(!watch_auth || auth_pointer == steps->borrowed_auth);
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->read_error}; http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; const reply *row = &steps->rows[http->calls - 1];
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, "Bearer ", 7) && !memcmp(steps->borrowed_auth + 7, row->key.data, row->key.len) && steps->borrowed_auth[row->key.len + 7] == '\0');
    CHECK(!watch_auth || auth_pointer == steps->borrowed_auth); steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *d, const reply *row)
{
    script steps = {.rows = row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "formbucket-offline"}; steps.ctx = &ctx;
    br_results results = scan_token(d, &ctx, true, row->key); CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_auth); return results;
}

static void outcomes(const br_detector *d)
{
    const struct { int status; br_slice body; const char *read_error; bool keep, verified; } cases[] = {
        {200, BYTES("created_on"), NULL, true, true}, {204, BYTES("unrelated created_on malformed"), NULL, true, true},
        {299, BYTES("\0\xff not_created_on_extra"), NULL, true, true},
        {200, BYTES("Created_On"), NULL, true, false}, {200, BYTES("{}"), NULL, true, false},
        {403, BYTES("created_on"), NULL, true, false}, {500, BYTES("created_on"), NULL, true, false},
        {200, BYTES("created_on"), "", false, false}, {500, BYTES("created_on"), "partial read", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reply row = {.key = BYTES("A.B.C"), .body = cases[i].body, .read_error = cases[i].read_error, .status = cases[i].status};
        br_results results = run(d, &row); CHECK(results.len == (cases[i].keep ? 1u : 0u));
        if (results.len) check_result(&results.items[0], row.key, cases[i].verified);
        br_results_clear(&results);
    }
    reply row = {.key = BYTES("A\xc3\xa9" "B.C"), .status = 200, .body = BYTES("created_on")};
    br_results results = run(d, &row); CHECK(results.len == 1); check_result(&results.items[0], row.key, true); br_results_clear(&results);
    row.key = BYTES("A\tB.C"); results = run(d, &row); CHECK(results.len == 1); check_result(&results.items[0], row.key, true); br_results_clear(&results);
    /* Other control bytes are NOT a new extraction/header policy: existing
     * whole shared send domain rejects them and the false finding stays. */
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    results = scan_token(d, &ctx, true, BYTES("A\rB.C")); CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(&results.items[0], BYTES("A\rB.C"), false); br_results_clear(&results);
    const char input[] = "formbucket A.B.C ; formbucket D!E.F ; formbucket A.B.C";
    reply rows[] = {{.key = BYTES("A.B.C"), .status = 200, .body = BYTES("created_on")},
                    {.key = BYTES("D!E.F"), .status = 204, .read_error = ""},
                    {.key = BYTES("A.B.C"), .status = 200, .body = BYTES("created_on"), .read_error = "read error after Do failed", .send_rc = -7, .send_error = "cannot create FormBucket result"}};
    script steps = {.rows = rows, .count = 3}; test_http scripted = {.inspect = inspect_request, .user = &steps}; br_transport injected = {&scripted, test_http_send, release_response};
    br_scan_ctx injected_ctx = {.transport = &injected, .user_agent = "formbucket-offline"}; steps.ctx = &injected_ctx;
    results = test_scan(d, &injected_ctx, true, input, sizeof(input) - 1); CHECK(results.len == 2 && scripted.calls == 3 && scripted.releases == 3 && !steps.borrowed_auth);
    check_result(&results.items[0], rows[0].key, true); check_result(&results.items[1], rows[2].key, false); br_results_clear(&results);
    results = test_scan(d, NULL, false, input, sizeof(input) - 1); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], rows[i].key, false);
    br_results_clear(&results);
    results = test_scan(d, NULL, true, input, sizeof(input) - 1); CHECK(!results.len && !results.items && !results.cap); br_results_clear(&results);
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

static void nul_ordering(const br_detector *d)
{
    br_slice key = BYTES("A\0B.C");
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    probe_auth(key.len, 1); br_results results = scan_token(d, NULL, true, key);
    CHECK(!results.len && !auth_arm && !auth_calls && !http.calls && !http.releases); br_results_clear(&results); stop_probe();
    probe_auth(key.len, 1); results = scan_token(d, &ctx, true, key);
    CHECK(results.len == 1 && auth_calls == 1 && auth_pointer && !http.calls && !http.releases); check_result(&results.items[0], key, false); br_results_clear(&results); stop_probe();
    /* Own mandatory allocation fails BEFORE the ordinary NUL guard, not after
     * a truncating send and not as an unverified finding or quiet drop. */
    results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
    const unsigned char input[] = "formbucket A\0B.C"; char *error = NULL; probe_auth(key.len, 2);
    CHECK(d->scan(d, &ctx, true, (br_slice){input, sizeof(input) - 1}, &results, &error) == -1 && error && !strcmp(error, "cannot allocate FormBucket authorization"));
    CHECK(auth_calls == 1 && !fail_after && !http.calls && !http.releases); check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results); stop_probe();
}

static void unbounded_authorization(const br_detector *d)
{
    size_t component = 2048, len = 3 * component + 2; unsigned char *key = malloc(len + 1); CHECK(key);
    memset(key, 'a', component); key[component] = '!'; memset(key + component + 1, 'B', component); key[2 * component + 1] = '.'; memset(key + 2 * component + 2, 'z', component); key[len] = '\0';
    reply row = {.key = {key, len}, .status = 200, .body = BYTES("created_on")};
    probe_auth(len, 1); br_results results = run(d, &row); CHECK(results.len == 1 && auth_calls == 1 && auth_pointer); check_result(&results.items[0], row.key, true); br_results_clear(&results); stop_probe();
    char *input = malloc(2 * len + 25); CHECK(input); size_t at = 0;
    memcpy(input + at, "formbucket ", 11); at += 11; memcpy(input + at, key, len); at += len; memcpy(input + at, " ;formbucket ", 13); at += 13; memcpy(input + at, key, len); at += len; input[at] = '\0';
    results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
    script steps = {.rows = &row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "formbucket-offline"}; steps.ctx = &ctx; char *error = NULL; probe_auth(len, 3);
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, at}, &results, &error) == -1 && error && !strcmp(error, "cannot allocate FormBucket authorization"));
    CHECK(auth_calls == 2 && !fail_after && http.calls == 1 && http.releases == 1 && !steps.borrowed_auth); check_prior(&results, raw, cause, parts);
    free(error); br_results_clear(&results); stop_probe(); free(input); free(key);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = scan_token(d, &ctx, true, BYTES("A.B.C"));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], BYTES("A.B.C"), false); br_results_clear(&results);
    }
    const char input[] = "formbucket A.B.C ; formbucket D!E.F"; br_slice data = BYTES(input);
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply row = {.key = BYTES("A.B.C"), .status = 200, .body = BYTES("created_on")}; script steps = {.rows = &row, .count = 1};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "formbucket-offline"}; steps.ctx = &ctx;
        char *error = NULL; fail_part_after = 2;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FormBucket result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls); check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1;
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FormBucket result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *d = descriptor(); extraction(d); outcomes(d); nul_ordering(d); unbounded_authorization(d); resources(d);
    return test_finish("FormBucket");
}
