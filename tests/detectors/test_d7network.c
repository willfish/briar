/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char ascii_key[] = "AbCdEfGhIjKlMnOpQrStUvW=";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Target actual own resources and positive helper failures; no auth heap seam. */
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

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(ascii_key) == 24);
    CHECK(br_d7network_init(NULL, &error) == -1 && error && !strcmp(error, "invalid D7Network detector output"));
    free(error); error = NULL;
    CHECK(br_d7network_init(NULL, NULL) == -1);
    CHECK(br_d7network_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_d7network_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 138 && detector->version == 0 && !strcmp(detector->name, "D7Network"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "D7Network provides messaging services through their API. The credentials can be used to send SMS and other types of messages via their platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "d7network"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, br_slice key, bool verified)
{
    CHECK(result->detector_type == 138 && !result->detector_name);
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
    char input[512], changed[26];
    const struct { const char *format; bool match; } cases[] = {
        {"d7network %s", true}, {"D7NeTwOrK:'%s'", true}, {"preD7NETWORKsuffix\r\n%s", true},
        {"%s d7network", false}, {"%s", false}, {"d7network%s", false},
        {"d7network x%s", false}, {"d7network _%s", false},
        {"d7network %sx", true}, {"d7network %s!", true}, {"d7network %s", true}, /* NO end boundary. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, ascii_key);
        extraction_case(detector, text(input), cases[i].match ? text(ascii_key) : (br_slice){0});
    }
    memset(changed, 'A', 22); changed[22] = '='; changed[23] = '\0';
    snprintf(input, sizeof(input), "d7network %s", changed);
    extraction_case(detector, text(input), text(changed)); /* Leading separator is captured then trimmed: no 24-byte minimum. */
    memset(changed, 'A', 24); changed[24] = '='; changed[25] = '\0';
    snprintf(input, sizeof(input), "d7network %s", changed);
    extraction_case(detector, text(input), (br_slice){0}); /* Fixed 23-rune count and leading boundary. */
    snprintf(input, sizeof(input), "d7network %.23s", ascii_key);
    extraction_case(detector, text(input), (br_slice){0});
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "d7network", 9); size_t at = 9;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, ascii_key, sizeof(ascii_key));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + 24}, gap == 40 ? text(ascii_key) : (br_slice){0});
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\nd7network %s\n\xff", ascii_key);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, text(ascii_key));
    memcpy(input, "d7network ", 10); memcpy(input + 10, ascii_key, sizeof(ascii_key)); input[15] = (char)0xff;
    extraction_case(detector, (br_slice){(const unsigned char *)input, 34}, (br_slice){0}); /* Core invalid-byte barrier inside capture. */
    extraction_case(detector, (br_slice){0}, (br_slice){0});
}

typedef struct {
    const br_slice *keys; size_t count;
    const char *agent, *borrowed_auth;
    br_slice borrowed_key;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && http->calls <= expected->count);
    br_slice key = expected->keys[http->calls - 1];
    CHECK(!memchr(key.data, '\0', key.len));
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://rest-api.d7networks.com/secure/balance"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 138);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 6 + key.len && auth[6 + key.len] == '\0' && !memcmp(auth, "Basic ", 6));
    CHECK(!memcmp(auth + 6, key.data, key.len)); /* Literal raw credential, NOT a Base64 encoding. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    expected->borrowed_auth = auth; expected->borrowed_key = key;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(!memcmp(expected->borrowed_auth, "Basic ", 6));
        CHECK(!memcmp(expected->borrowed_auth + 6, expected->borrowed_key.data, expected->borrowed_key.len));
        CHECK(expected->borrowed_auth[6 + expected->borrowed_key.len] == '\0'); /* Stack survives release. */
        expected->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void rune_capture(const br_detector *detector, const char *prefix, br_slice capture, br_slice expected)
{
    unsigned char input[256]; size_t n = strlen(prefix);
    CHECK(n + capture.len < sizeof(input)); memcpy(input, prefix, n); memcpy(input + n, capture.data, capture.len);
    extraction_case(detector, (br_slice){input, n + capture.len}, expected);
    expected_http requests = {.keys = &expected, .count = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect_request, .user = &requests};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, n + capture.len);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], expected, true); br_results_clear(&results);
}

static void runes_and_trim(const br_detector *detector)
{
    const char *runes[] = {"\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80"};
    unsigned char capture[94];
    for (size_t width = 0; width < 3; ++width) {
        size_t at = 0;
        for (size_t r = 0; r < 23; ++r) { memcpy(capture + at, runes[width], strlen(runes[width])); at += strlen(runes[width]); }
        capture[at++] = '=';
        CHECK(at == 23 * (width + 2) + 1);
        rune_capture(detector, "d7network", (br_slice){capture, at}, (br_slice){capture, at}); /* 47/70/93 bytes; max header 99 + NUL. */
    }
    const char spaces[] = " \t\n\v\f\r\xc2\x85\xc2\xa0\xe1\x9a\x80\xe2\x80\x80\xe2\x80\x8a"
                          "\xe2\x80\xa8\xe2\x80\xa9\xe2\x80\xaf\xe2\x81\x9f\xe3\x80\x80       =";
    rune_capture(detector, "d7network", text(spaces), text("=")); /* All Go space ranges; raw can be ONE byte. */
    memcpy(capture, "\xe2\x80\x8b", 3); memset(capture + 3, 'A', 22); capture[25] = '=';
    rune_capture(detector, "d7network", (br_slice){capture, 26}, (br_slice){capture, 26}); /* U+200B is NOT Go whitespace. */
    memcpy(capture, ascii_key, 24); capture[8] = '\t';
    rune_capture(detector, "d7network ", (br_slice){capture, 24}, (br_slice){capture, 24}); /* Interior HTAB survives. */
    memcpy(capture, ascii_key, 7); memcpy(capture + 7, "\xef\xbf\xbd", 3); memcpy(capture + 10, ascii_key + 8, 16);
    rune_capture(detector, "d7network ", (br_slice){capture, 26}, (br_slice){capture, 26}); /* Valid U+FFFD is preserved, not a bad-byte barrier. */

    char input[256], raw[24]; memset(raw, 'A', 22); raw[22] = '='; raw[23] = '\0';
    int n = snprintf(input, sizeof(input), "d7network %s\nd7network\xc2\xa0%s\nd7network %s", raw, raw, raw);
    br_slice keys[] = {text(raw), text(raw), text(raw)};
    expected_http expected = {.keys = keys, .count = 3, .agent = "TruffleHog d7network-offline"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "d7network-offline"};
    br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true); /* No post-trim dedup/cache. */
    br_results_clear(&results);
}

static void nul_and_unsafe_controls(const br_detector *detector)
{
    unsigned char key[24], input[34]; memcpy(key, ascii_key, 24); key[6] = 0;
    memcpy(input, "d7network ", 10); memcpy(input + 10, key, 24);
    extraction_case(detector, (br_slice){input, sizeof(input)}, (br_slice){key, sizeof(key)});
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, sizeof(input));
    CHECK(results.len == 1 && !http.calls && !http.releases);
    check_result(&results.items[0], (br_slice){key, sizeof(key)}, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, sizeof(input));
    CHECK(!results.len); br_results_clear(&results); /* Nil constructor skip precedes NUL keep guard. */
    const unsigned char controls[] = {'\r', '\n', '\v', 1, 0x7f};
    for (size_t i = 0; i < sizeof(controls); ++i) {
        key[6] = controls[i]; memcpy(input + 10, key, 24); http.calls = http.releases = 0;
        extraction_case(detector, (br_slice){input, sizeof(input)}, (br_slice){key, sizeof(key)});
        results = test_scan(detector, &ctx, true, input, sizeof(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1); /* Actual shared header validation suppresses without truncation/sanitization. */
        check_result(&results.items[0], (br_slice){key, sizeof(key)}, false); br_results_clear(&results);
    }
}

static void verification(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "d7network %s", ascii_key);
    br_slice key = text(ascii_key); expected_http expected = {.keys = &key, .count = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, "ignored", true},
        {204, 0, NULL, "", true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, NULL, false}, {403, 0, NULL, "ignored", false}, {500, 0, NULL, NULL, false},
        {200, 1, "net/http: nil Context", NULL, false}, {200, -1, "synthetic timeout", "ignored", false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false}, {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "d7network %s", ascii_key);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, (size_t)n);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], text(ascii_key), false); br_results_clear(&results);
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
    char input[256]; int n = snprintf(input, sizeof(input), "d7network %s\nd7network %s", ascii_key, ascii_key);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create D7Network result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    unsigned char binary[34]; memcpy(binary, "d7network ", 10); memcpy(binary + 10, ascii_key, 24); binary[16] = 0;
    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){binary, sizeof(binary)}, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create D7Network result") && !fail_part_after && !http.calls && !http.releases);
    check_prior(&results, prior); free(error); error = NULL; /* Resource error beats NUL retention. */
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create D7Network result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 25; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 24; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create D7Network result") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append D7Network result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], text(ascii_key), true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); runes_and_trim(detector); nul_and_unsafe_controls(detector);
    verification(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("D7Network all-rune captures + Go trim + literal PUBLIC Basic + NUL guard + rollback");
}
