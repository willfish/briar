/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key1[] = "Ab3dEf6hIj9kLm2nOp5q", key2[] = "Z9y8X7w6V5u4T3s2R1q0";
static const char id1[] = "A$%^=-z9", id2[] = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_add_after;
typedef struct { const char *const *keys, *const *ids; size_t len; const char *borrowed_auth; } expected_requests;

/* Real positive +1 composite finding-part failure, also before constructor skip.
 * No artificial auth-allocation seam; normal ownership remains with add_ex. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_companyhub_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_companyhub_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 256 && detector->version == 0 && !strcmp(detector->name, "CompanyHub"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "CompanyHub is a CRM tool used to manage customer relationships. CompanyHub keys can be used to access and manipulate CRM data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "companyhub"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_companyhub_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void pair_result(const br_result *result, const char *key, const char *id)
{
    size_t idlen = strlen(id);
    CHECK(strlen(key) == 20 && idlen >= 4 && idlen <= 32);
    CHECK(result->detector_type == 256 && result->raw.len == 20 && !memcmp(result->raw.data, key, 20));
    CHECK(result->raw_v2.len == 20 + idlen && !memcmp(result->raw_v2.data, key, 20));
    CHECK(!memcmp(result->raw_v2.data + 20, id, idlen));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), key, 20));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == idlen && !memcmp(json_object_get_string(part), id, idlen));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static void no_verify(const br_detector *detector, const char *input,
                       const char *const *keys, const char *const *ids, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        pair_result(&results.items[i], keys[i], ids[i]); CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void id_field(const br_detector *detector, const char *gap, const char *field, const char *projected)
{
    char input[512]; snprintf(input, sizeof(input), "companyhub %s;\n%s\ncompanyhub%s%s", key1, isolation, gap, field);
    const char *keys[] = {key1, key1}, *ids[] = {key1, projected};
    /* The key line is itself an ID occurrence: negative ID cases still self-pair. */
    no_verify(detector, input, keys, ids, projected ? 2 : 1);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[34]; const char *keys[] = {key1}, *ids[] = {key1};
    snprintf(input, sizeof(input), "CoMpAnYhUb %s", key1); no_verify(detector, input, keys, ids, 1);
    no_verify(detector, key1, NULL, NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[19] = 0;
    snprintf(input, sizeof(input), "companyhub %s", changed); no_verify(detector, input, NULL, NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[20] = 'A'; changed[21] = 0;
    snprintf(input, sizeof(input), "companyhub %s", changed); no_verify(detector, input, NULL, NULL, 0);
    snprintf(input, sizeof(input), "companyhub _%s", key1); no_verify(detector, input, NULL, NULL, 0);
    snprintf(input, sizeof(input), "companyhub %s_", key1); no_verify(detector, input, NULL, NULL, 0);
    id_field(detector, " ", id1, id1); id_field(detector, " ", id2, id2);
    id_field(detector, " ", "A1b", NULL); id_field(detector, " ", "A1b2", "A1b2");
    memset(changed, 'a', 33); changed[33] = 0; id_field(detector, " ", changed, NULL);
    id_field(detector, " ", "AbCd_EfGh", NULL);
    id_field(detector, " ", "Abc$", NULL); id_field(detector, " ", "Abcd$", "Abcd"); /* Variable-length backtracking. */
    id_field(detector, " ", "$Abc", NULL); id_field(detector, "", "$Abc", "$Abc"); /* Word b before nonword '$'. */
    char projected[33]; memset(projected, 'a', 31); projected[31] = '$'; projected[32] = 0;
    snprintf(changed, sizeof(changed), "%sZ", projected); id_field(detector, " ", changed, projected); /* Max32 ends '$' before word Z. */
    const char *context_ids[] = {"token"}, *provider_ids[] = {"companyhub"};
    snprintf(input, sizeof(input), "companyhub token %s", key1); no_verify(detector, input, keys, context_ids, 1);
    snprintf(input, sizeof(input), "companyhub companyhub %s", key1); no_verify(detector, input, keys, provider_ids, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, '.', gap); padding[gap] = 0;
        snprintf(input, sizeof(input), "companyhub%s%s", padding, key1); no_verify(detector, input, keys, ids, gap == 40 ? 1 : 0);
        id_field(detector, padding, id2, gap == 40 ? id2 : NULL);
    }
    memset(changed, 'A', 20); changed[20] = 0;
    const char *simple_keys[] = {changed}, *simple_ids[] = {changed};
    snprintf(input, sizeof(input), "companyhub %s", changed); no_verify(detector, input, simple_keys, simple_ids, 1); /* No entropy filter/equality skip. */
    no_verify(detector, NULL, NULL, NULL, 0);
}

static void auth_value(const char *auth, const char *key, const char *id)
{
    size_t n = strlen(id);
    CHECK(n >= 4 && n <= 32 && strlen(key) == 20);
    CHECK(strlen(auth) == n + 21 && !memcmp(auth, id, n));
    CHECK(auth[n] == ' ' && !memcmp(auth + n + 1, key, 20) && auth[n + 21] == '\0');
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 256);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.companyhub.com/v1/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    auth_value(request->headers[0].value, expected->keys[http->calls - 1], expected->ids[http->calls - 1]);
    expected->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog companyhub-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source scan-deferred close-only. */
}

static void release_auth(void *user, br_http_response *response)
{
    test_http *http = user; expected_requests *expected = http->user;
    if (http->calls > http->releases) {
        CHECK(expected->borrowed_auth); /* The shared adapter has already freed its header array. */
        auth_value(expected->borrowed_auth, expected->keys[http->calls - 1], expected->ids[http->calls - 1]);
    } else CHECK(!expected->borrowed_auth);
    expected->borrowed_auth = NULL;
    test_http_release(user, response);
}

static void products_and_skip(const br_detector *detector)
{
    char input[1024]; snprintf(input, sizeof(input), "companyhub %s;\n%s\nCOMPANYHUB %s;\n%s\ncompanyhub %s;\n%s\ncompanyhub %s;\n%s\ncompanyhub %s;\n%s\ncompanyhub %s",
                              key1, isolation, key2, isolation, key1, isolation, id1, isolation, id2, isolation, id1);
    const char *key_occurrences[] = {key1, key2, key1}, *id_occurrences[] = {key1, key2, key1, id1, id2, id1};
    const char *keys[18], *ids[18];
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 6; ++i) { keys[k * 6 + i] = key_occurrences[k]; ids[k * 6 + i] = id_occurrences[i]; }
    expected_requests expected = {.keys = keys, .ids = ids, .len = 18};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); transport.release = release_auth; br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 18 && http.calls == (mode ? 18u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 18; ++i) {
            pair_result(&results.items[i], keys[i], ids[i]); CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 18u));
        for (size_t i = 0; i < results.len; ++i) {
            pair_result(&results.items[i], keys[i], ids[i]); CHECK(!results.items[i].verified && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[128], sensitive[128]; snprintf(input, sizeof(input), "companyhub %s", key1);
    snprintf(sensitive, sizeof(sensitive), "synthetic Authorization: %s %s", key1, key1);
    const char *keys[] = {key1}, *ids[] = {key1}; expected_requests expected = {.keys = keys, .ids = ids, .len = 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "out of memory constructing HTTP headers", false},
        {200, 1, "unsupported: native HTTP client configuration", false}, {200, 1, NULL, false},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); transport.release = release_auth;
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "companyhub-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); pair_result(&results.items[0], key1, key1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "companyhub %s", key1);
    const char *keys[] = {key1}, *ids[] = {key1}; expected_requests expected = {.keys = keys, .ids = ids, .len = 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http); transport.release = release_auth;
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); pair_result(&results.items[0], key1, key1);
        CHECK(!results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_add_after = 2;
    CHECK(br_finding_pair(&probe, 256, key1, "key", id1, "id") != 0 && !fail_add_after);
    CHECK(!probe.raw.data && !probe.raw_v2.data && !probe.secret_parts); br_result_clear(&probe); CHECK(br_results_push(NULL, &probe) == 1);
    char input[256]; snprintf(input, sizeof(input), "companyhub %s;\n%s\ncompanyhub %s", key1, isolation, key2);
    const char *keys[] = {key1, key1, key2, key2}, *ids[] = {key1, key2, key1, key2};
    expected_requests expected = {.keys = keys, .ids = ids, .len = 4};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); transport.release = release_auth; br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_add_after = 4; /* Second pair's ID part, after first pair was appended. */
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating CompanyHub result"));
    CHECK(!fail_add_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL; fail_add_after = 2;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating CompanyHub result"));
    CHECK(!fail_add_after && results.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(results.items[0].raw.data == original_raw && results.items[0].verification_error == original_error);
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < 4; ++i) { pair_result(&results.items[i], keys[i], ids[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 20 && strlen(key2) == 20 && strlen(id1) == 8 && strlen(id2) == 32);
    const br_detector *detector = descriptor();
    extraction(detector); products_and_skip(detector); statuses_and_errors(detector); contexts(detector); resource_rollback(detector);
    return test_finish("CompanyHub");
}
