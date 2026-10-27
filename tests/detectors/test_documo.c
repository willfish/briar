/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static unsigned char key1[244], key2[244];
static size_t key1_len, key2_len, fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Actual finding/capture/shared-send resources, never a heap auth substitute. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static size_t make_key(unsigned char out[244], br_slice first, br_slice second, size_t shift)
{
    memcpy(out, "ey", 2); test_secret((char *)out + 2, 34, shift); out[9] = 'A';
    size_t at = 36; memcpy(out + at, first.data, first.len); at += first.len;
    memcpy(out + at, "ey", 2); at += 2;
    test_secret((char *)out + at, 154, shift + 7); out[at + 13] = 'G'; at += 154;
    memcpy(out + at, second.data, second.len); at += second.len;
    test_secret((char *)out + at, 43, shift + 13); out[at + 10] = '_'; out[at + 18] = '-'; out[at + 42] = 'Z'; at += 43;
    out[at] = '\0'; return at;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && key1_len == 237 && key2_len == 243);
    CHECK(br_documo_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Documo detector output"));
    free(error); error = NULL;
    CHECK(br_documo_init(NULL, NULL) == -1);
    CHECK(br_documo_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_documo_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 311 && detector->version == 0 && !strcmp(detector->name, "Documo"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "A service for creating and modifying documents. API keys can create read update and delete documents."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "documo")); /* Dispatch only, NOT extraction prefix. */
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, br_slice key, bool verified)
{
    CHECK(result->detector_type == 311 && !result->detector_name);
    CHECK(result->raw.len == key.len && !memcmp(result->raw.data, key.data, key.len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == key.len && !memcmp(json_object_get_string(part), key.data, key.len));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, br_slice input, br_slice expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected.data ? 1u : 0u) && !http.calls && !http.releases);
    if (expected.data) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    br_slice base = {key1, key1_len}; unsigned char input[512], changed[244];
    extraction_case(detector, base, base); /* Bare token, no documo/PrefixRegex requirement. */
    memcpy(input, "unrelated ", 10); memcpy(input + 10, key1, key1_len);
    extraction_case(detector, (br_slice){input, 10 + key1_len}, base);
    input[0] = 'x'; memcpy(input + 1, key1, key1_len);
    extraction_case(detector, (br_slice){input, 1 + key1_len}, (br_slice){0});
    input[0] = '_'; extraction_case(detector, (br_slice){input, 1 + key1_len}, (br_slice){0});
    memcpy(input, key1, key1_len); input[key1_len] = 'x';
    extraction_case(detector, (br_slice){input, key1_len + 1}, (br_slice){0});
    input[key1_len] = '_'; extraction_case(detector, (br_slice){input, key1_len + 1}, (br_slice){0});
    memcpy(input, "\xc3\xa9", 2); memcpy(input + 2, key1, key1_len); memcpy(input + 2 + key1_len, "\xc3\xa9", 2);
    extraction_case(detector, (br_slice){input, key1_len + 4}, base);
    const size_t positions[] = {0, 37, 5, 41, 205};
    const unsigned char invalid[] = {'E', 'E', '_', '-', '+'};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, key1, key1_len); changed[positions[i]] = invalid[i];
        extraction_case(detector, (br_slice){changed, key1_len}, (br_slice){0});
    }
    memcpy(changed, key1, key1_len); changed[key1_len - 1] = '-';
    extraction_case(detector, (br_slice){changed, key1_len}, (br_slice){0});
    memcpy(input, changed, key1_len); input[key1_len] = 'X';
    extraction_case(detector, (br_slice){input, key1_len + 1}, (br_slice){changed, key1_len}); /* End boundary can be nonword '-' -> word X. */
    extraction_case(detector, (br_slice){key1, key1_len - 1}, (br_slice){0});
    size_t n = make_key(changed, text("\n"), text("."), 0);
    extraction_case(detector, (br_slice){changed, n}, (br_slice){0});
    n = make_key(changed, text("."), text("\n"), 0);
    extraction_case(detector, (br_slice){changed, n}, (br_slice){0});
    static const unsigned char bad_byte[] = {0xff};
    n = make_key(changed, (br_slice){bad_byte, 1}, text("."), 0);
    extraction_case(detector, (br_slice){changed, n}, (br_slice){0}); /* Shared invalid-byte barrier, no whole-input guard. */
    input[0] = 0xff; input[1] = '\n'; memcpy(input + 2, key1, key1_len); input[2 + key1_len] = 0xff;
    extraction_case(detector, (br_slice){input, key1_len + 3}, base);
    extraction_case(detector, (br_slice){0}, (br_slice){0});
}

typedef struct {
    const br_slice *keys; size_t count;
    const char *agent, *borrowed_auth;
    br_slice current_key;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    br_slice key = expected->keys[http->calls - 1]; CHECK(!memchr(key.data, 0, key.len));
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.documo.com/v1/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 311);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    const char *auth = request->headers[1].value;
    CHECK(strlen(auth) == 6 + key.len && auth[6 + key.len] == '\0' && !memcmp(auth, "Basic ", 6));
    CHECK(!memcmp(auth + 6, key.data, key.len)); /* Literal full raw key, NOT a Basic/Base64 encoder. */
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    expected->borrowed_auth = auth; expected->current_key = key;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(!memcmp(expected->borrowed_auth, "Basic ", 6) && !memcmp(expected->borrowed_auth + 6, expected->current_key.data, expected->current_key.len));
        CHECK(expected->borrowed_auth[6 + expected->current_key.len] == '\0'); /* Max 249 header bytes + NUL survive release. */
        expected->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void wildcard_bytes(const br_detector *detector)
{
    unsigned char key[244]; size_t n = make_key(key, text(" "), text("\t"), 0);
    br_slice selected = {key, n}; extraction_case(detector, selected, selected);
    expected_http expected = {.keys = &selected, .count = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, key, n);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], selected, true); br_results_clear(&results);
    selected = (br_slice){key2, key2_len}; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key2, key2_len);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], selected, true); br_results_clear(&results);
    const unsigned char unsafe[] = {'\r', '\v', 1, 0x7f};
    for (size_t i = 0; i < sizeof(unsafe); ++i) {
        n = make_key(key, (br_slice){unsafe + i, 1}, text("."), 0); selected = (br_slice){key, n};
        extraction_case(detector, selected, selected); http.calls = http.releases = 0;
        results = test_scan(detector, &ctx, true, key, n);
        CHECK(results.len == 1 && !http.calls && http.releases == 1); /* Existing shared validation suppresses invalid headers, never narrows extraction. */
        check_result(&results.items[0], selected, false); br_results_clear(&results);
    }
    static const unsigned char nul[] = {0};
    n = make_key(key, text("."), (br_slice){nul, 1}, 0); selected = (br_slice){key, n};
    extraction_case(detector, selected, selected); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, n);
    CHECK(results.len == 1 && !http.calls && !http.releases); check_result(&results.items[0], selected, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, key, n);
    CHECK(!results.len); br_results_clear(&results); /* Constructor skip precedes NUL false-retention guard. */
}

static void occurrences_and_statuses(const br_detector *detector)
{
    unsigned char input[1024]; size_t at = 0;
    br_slice keys[] = {{key1, key1_len}, {key2, key2_len}, {key1, key1_len}};
    for (size_t i = 0; i < 3; ++i) { memcpy(input + at, keys[i].data, keys[i].len); at += keys[i].len; input[at++] = '\n'; }
    expected_http expected = {.keys = keys, .count = 3, .agent = "TruffleHog documo-offline"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "documo-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, at); CHECK(!results.len); br_results_clear(&results);
    expected.count = 1; expected.agent = "TruffleHog"; ctx.user_agent = NULL;
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, "ignored", true},
        {204, 0, NULL, "", true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, "ignored", false}, {403, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, -1, "synthetic timeout", "ignored", false}, {200, 1, "net/http: nil Context", NULL, false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false}, {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        http.send_rc = cases[i].rc; http.send_error = cases[i].cause;
        results = test_scan(detector, &ctx, true, key1, key1_len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], keys[0], cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, key1, key1_len);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], (br_slice){key1, key1_len}, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    unsigned char input[512], binary[244]; memcpy(input, key1, key1_len); input[key1_len] = '\n'; memcpy(input + key1_len + 1, key1, key1_len);
    br_slice data = {input, 2 * key1_len + 1};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Documo result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    static const unsigned char nul[] = {0}; size_t n = make_key(binary, (br_slice){nul, 1}, text("."), 0);
    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){binary, n}, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Documo result") && !fail_part_after && !http.calls && !http.releases);
    check_prior(&results, prior); free(error); error = NULL; /* Finding failure wins before the NUL guard. */
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Documo result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = key1_len + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Skips never append. */
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Documo result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, data.data, data.len);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], (br_slice){key1, key1_len}, true);
    br_results_clear(&results);
}

int main(void)
{
    key1_len = make_key(key1, text("."), text("."), 0);
    key2_len = make_key(key2, text("\xf0\x9f\x98\x80"), text("\xf0\x90\x90\xb7"), 7);
    const br_detector *detector = descriptor();
    extraction(detector); wildcard_bytes(detector); occurrences_and_statuses(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("Documo");
}
