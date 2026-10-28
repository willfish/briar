/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[41], key2[41];
static const char quote_prefix[] = "got HTTP 200 with unexpected Content-Type ";
static const char unsupported_quote[] = "unsupported: Enigma non-ASCII Content-Type diagnostic requires Go quoting";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_duplicate_after;
static size_t watched_size, watched_allocations;
static const char *fail_duplicate_text;
static bool fail_agent_copy;

/* Actual capture/finding/cause/setter/shared-send resources, not auth/body seams. */
void *malloc(size_t size)
{
    if (watched_size && size == watched_size) ++watched_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    if (fail_duplicate_after && fail_duplicate_text && !strcmp(text, fail_duplicate_text) && --fail_duplicate_after == 0) return NULL;
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 40 && strlen(key2) == 40);
    CHECK(br_enigma_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Enigma detector output"));
    free(error); error = NULL;
    CHECK(br_enigma_init(NULL, NULL) == -1);
    CHECK(br_enigma_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_enigma_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 405 && detector->version == 0 && !strcmp(detector->name, "Enigma"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Enigma is a business data intelligence platform. Enigma API keys grant access to comprehensive firmographic, legal, and identity datasets."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "enigma"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector; /* Exact EnigmaDetectorEnabled selection remains parent-owned. */
}

static void check_result(const br_result *result, const char *key, bool verified, const char *cause)
{
    test_key_result(result, 405, key, "key");
    CHECK(result->raw.len == 40 && result->verified == verified && !result->verification_from_cache);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 40);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[41];
    const struct { const char *format; bool matches; } cases[] = {
        {"enigma '%s'", true}, {"ENigMA=%s", true}, {"preenigmasuffix:%s", true},
        {"enigma\r\n%s", true}, {"enigma\r%s", true}, {"enigma\n%s", true},
        {"%s", false}, {"%s enigma", false}, {"enig ma %s", false}, {"enigma%s", false},
        {"enigma x%s", false}, {"enigma _%s", false}, {"enigma %s_", false}, {"enigma %s9", false},
        {"enigma %.39s", false}, {"enigma \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char invalid[] = "_-+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "enigma %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'a', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "enigma %s", changed); extraction_case(detector, input, strlen(input), changed); /* No entropy or token validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "enigma", 6); size_t at = 6;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, 40); at += 40;
            extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "enigma%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\nenigma %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "enigma %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { int status, rc; const br_header *headers; size_t count; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *keys; size_t count;
    const reply *replies;
    const char *agent, *borrowed_key, *current_key;
    br_slice borrowed_body;
    const br_scan_ctx *original;
    char *owned_error, *clobber_header;
    bool clobber_error;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char body[] = "{\"query\":\"{ __typename }\"}";
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1]; const reply *r = &expected->replies[http->calls - 1];
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.enigma.com/graphql"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 405);
    CHECK(request->nheaders == 3 && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "x-api-key") && !memcmp(request->headers[1].value, key, 41));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    CHECK(sizeof(body) == 27 && request->body.len == 26 && !memcmp(request->body.data, body, sizeof(body)));
    CHECK(!expected->borrowed_key && !expected->borrowed_body.data);
    expected->borrowed_key = request->headers[1].value; expected->borrowed_body = request->body; expected->current_key = key;
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    http->response = (br_http_response){.status = r->status, .headers = r->headers, .nheaders = r->count, .body = {ignored, sizeof(ignored)}, .body_error = r->read_error};
    http->send_rc = r->rc; http->send_error = r->send_error;
}

static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; expected_http *expected = http->user;
    expected->owned_error = *error;
    return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_key) {
        CHECK(!memcmp(expected->borrowed_key, expected->current_key, 41));
        CHECK(expected->borrowed_body.len == 26 && !memcmp(expected->borrowed_body.data, "{\"query\":\"{ __typename }\"}", 27));
        expected->borrowed_key = NULL; expected->borrowed_body = (br_slice){0};
    }
    if (expected && expected->clobber_error && expected->owned_error) expected->owned_error[0] = 'X';
    if (expected && expected->clobber_header) expected->clobber_header[0] = '!';
    if (expected) expected->owned_error = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, send_request, release_response};
}

static void verification_case(const br_detector *detector, const char *key, reply response, bool verified, const char *cause)
{
    char input[64]; snprintf(input, sizeof(input), "enigma %s", key);
    const char *keys[] = {key}; expected_http expected = {.keys = keys, .count = 1, .replies = &response, .agent = "TruffleHog", .clobber_error = true};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_key && !expected.borrowed_body.data);
    check_result(&results.items[0], key, verified, cause); br_results_clear(&results);
}

static void occurrences_and_nil(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "enigma %s\nENIGMA %s\nenigma %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; const br_header headers[] = {{"Content-Type", "application/json"}};
    const reply replies[] = {{200, 0, headers, 1, "ignored", NULL}, {200, 0, headers, 1, "", NULL}, {200, 0, headers, 1, NULL, NULL}};
    expected_http expected = {.keys = keys, .count = 3, .replies = replies, .agent = "TruffleHog enigma-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "enigma-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false, NULL);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true, NULL);
        br_results_clear(&results);
    }
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false, "net/http: nil Context");
    br_results_clear(&results);
}

static void header_and_status_policy(const br_detector *detector)
{
    const br_header json[] = {{"cOnTeNt-TyPe", "application/json; charset=utf-8"}};
    const br_header substring[] = {{"Content-Type", "nonsense \"Xapplication/jsonY\""}};
    const br_header upper[] = {{"Content-Type", "Application/JSON"}};
    const br_header spaces[] = {{"Content-Type", " text/html "}};
    const br_header bad_first[] = {{"Content-Type", "text/html"}, {"content-type", "application/json"}};
    const br_header empty_first[] = {{"Content-Type", ""}, {"Content-Type", "application/json"}};
    const br_header good_first[] = {{"Content-Type", "application/json"}, {"Content-Type", "text/html"}};
    const br_header other[] = {{"X-Other", "application/json"}};
    const br_header unicode_good[] = {{"Content-Type", "\xce\xbb application/json \xf0\x9f\x98\x80"}};
    const br_header unrelated_unicode[] = {{"Content-Type", "text/html"}, {"X-Other", "\xce\xbb"}};
    verification_case(detector, key1, (reply){200, 0, json, 1, "", NULL}, true, NULL);
    verification_case(detector, key1, (reply){200, 0, substring, 1, "ignored", NULL}, true, NULL);
    verification_case(detector, key1, (reply){200, 0, upper, 1, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"Application/JSON\"");
    verification_case(detector, key1, (reply){200, 0, spaces, 1, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \" text/html \"");
    verification_case(detector, key1, (reply){200, 0, bad_first, 2, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"text/html\"");
    verification_case(detector, key1, (reply){200, 0, empty_first, 2, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"\"");
    verification_case(detector, key1, (reply){200, 0, good_first, 2, NULL, NULL}, true, NULL);
    verification_case(detector, key1, (reply){200, 0, other, 1, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"\"");
    verification_case(detector, key1, (reply){.status = 200}, false, "got HTTP 200 with unexpected Content-Type \"\"");
    verification_case(detector, key1, (reply){200, 0, unicode_good, 1, "ignored", NULL}, true, NULL);
    verification_case(detector, key1, (reply){200, 0, unrelated_unicode, 2, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"text/html\"");
    const br_header unicode_bad[] = {{"Content-Type", "\xce\xbb"}};
    const int statuses[] = {199, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        verification_case(detector, key1, (reply){statuses[i], 0, unicode_bad, 1, "ignored", NULL}, false, statuses[i] == 401 ? NULL : cause);
    } /* Non-200 never quotes or guards non-ASCII Content-Type. */
    char echo[128], redacted[128]; snprintf(echo, sizeof(echo), "Do %s / %s", key1, key2); snprintf(redacted, sizeof(redacted), "Do [REDACTED] / %s", key2);
    verification_case(detector, key1, (reply){200, 1, unicode_bad, 1, NULL, echo}, false, redacted);
    verification_case(detector, key1, (reply){.status = 200, .rc = 1}, false, "HTTP transport failed");
}

static void exact_ascii_quoting(const br_detector *detector)
{
    char controls[40]; for (unsigned i = 1; i <= 31; ++i) controls[i - 1] = (char)i;
    controls[31] = 0x7f; strcpy(controls + 32, " \"\\'/~");
    const br_header header[] = {{"Content-Type", controls}};
    const char golden[] = "got HTTP 200 with unexpected Content-Type \""
        "\\x01\\x02\\x03\\x04\\x05\\x06\\a\\b\\t\\n\\v\\f\\r"
        "\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x7f"
        " \\\"\\\\'/~\"";
    verification_case(detector, key1, (reply){200, 0, header, 1, "ignored", NULL}, false, golden);
    char generated_key[41], value[39]; memcpy(generated_key, "x01", 3); memset(generated_key + 3, 'a', 37); generated_key[40] = '\0';
    value[0] = 1; memset(value + 1, 'a', 37); value[38] = '\0';
    const br_header creates_token[] = {{"Content-Type", value}};
    verification_case(detector, generated_key, (reply){200, 0, creates_token, 1, NULL, NULL}, false, "got HTTP 200 with unexpected Content-Type \"\\[REDACTED]\""); /* Quoting creates the token spelling; redact AFTER, never before. */

    const size_t len = 8192, position = 4096, prefix = sizeof(quote_prefix) - 1;
    char *large = malloc(len + 1), *wanted = malloc(prefix + len + 3); CHECK(large && wanted);
    memset(large, 'x', len); memcpy(large + position, key1, 40); large[len] = '\0';
    size_t at = 0; memcpy(wanted, quote_prefix, prefix); at += prefix; wanted[at++] = '"';
    memcpy(wanted + at, large, position); at += position; memcpy(wanted + at, "[REDACTED]", 10); at += 10;
    memcpy(wanted + at, large + position + 40, len - position - 40); at += len - position - 40; wanted[at++] = '"'; wanted[at] = '\0';
    const br_header long_header[] = {{"Content-Type", large}}; const reply response = {200, 0, long_header, 1, NULL, NULL};
    const char *keys[] = {key1}; expected_http expected = {.keys = keys, .count = 1, .replies = &response, .agent = "TruffleHog", .clobber_header = large};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[64]; snprintf(input, sizeof(input), "enigma %s", key1);
    watched_size = prefix + len + 3; size_t before = watched_allocations;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && watched_allocations == before + 2); /* One EXACT complete cause allocation, then the required setter copy. */
    CHECK(large[0] == '!'); check_result(&results.items[0], key1, false, wanted);
    br_results_clear(&results); watched_size = 0; free(large); free(wanted);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_causes(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "enigma %s", key1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, false, causes[i]); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources_and_unicode(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "enigma %s\nenigma %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)}; br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const br_header json[] = {{"Content-Type", "application/json"}}, html[] = {{"Content-Type", "text/html"}}, unicode[] = {{"Content-Type", "\xce\xbb"}};
    const char *keys[] = {key1, key2}; reply replies[] = {{200, 0, json, 1, NULL, NULL}, {200, 0, html, 1, "ignored", NULL}};
    expected_http expected = {.keys = keys, .count = 2, .replies = replies, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Enigma result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_duplicate_text = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot set Enigma verification error") && !fail_duplicate_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Enigma result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    replies[1].headers = unicode; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, unsupported_quote) && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL; /* Non-ASCII guard is explicit fatal, with prior verified result rolled back. */
    replies[1].headers = html; http.calls = http.releases = 0;
    fail_alloc_size = sizeof(quote_prefix) - 1 + strlen("text/html") + 3; fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate Enigma Content-Type cause") && !fail_alloc_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_duplicate_text = "got HTTP 200 with unexpected Content-Type \"text/html\""; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set Enigma verification error") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 41; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Enigma result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, true, NULL); check_result(&results.items[1], key2, false, "got HTTP 200 with unexpected Content-Type \"text/html\""); br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 40, 0); test_secret(key2, 40, 7); key1[8] = 'A'; key1[22] = 'G'; key1[39] = 'Z'; key2[8] = 'G'; key2[22] = 'A'; key2[39] = 'K';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil(detector); header_and_status_policy(detector); exact_ascii_quoting(detector); setup_causes(detector); fatal_resources_and_unicode(detector);
    return test_finish("Enigma ASCII diagnostics + explicit non-ASCII diagnostic boundary");
}
