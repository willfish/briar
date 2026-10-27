/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

static const char key1[] = "Gh7Jk9Lm2Np4Q";
static const char key2[] = "Z9y8X7w6V5u4T";
static const char url_format[] = "https://api.debounce.io/v1/?api=%.*s&email=some@gmail.com";
static size_t formatted_urls, fail_format_after, fail_alloc_size, fail_alloc_after, fail_part_after;
static bool truncate_format;

/* Fail actual resource/format boundaries, never an invented heap URL seam. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static bool fail_format(const char *format)
{
    if (strcmp(format, url_format)) return false;
    ++formatted_urls;
    return fail_format_after && --fail_format_after == 0;
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
    if (fail_format(format)) return truncate_format ? (int)size : -1;
    va_list args; va_start(args, format);
    int n = vsnprintf(buffer, size, format, args);
    va_end(args); return n;
}

#if defined(__GLIBC__) && defined(__USE_FORTIFY_LEVEL) && __USE_FORTIFY_LEVEL > 0
int __snprintf_chk(char *buffer, size_t size, int flag, size_t capacity, const char *format, ...)
{
    if (fail_format(format)) return truncate_format ? (int)size : -1;
    va_list args; va_start(args, format);
    int n = __vsnprintf_chk(buffer, size, flag, capacity, format, args);
    va_end(args); return n;
}
#endif

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 13 && strlen(key2) == 13);
    CHECK(br_debounce_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Debounce detector output"));
    free(error); error = NULL;
    CHECK(br_debounce_init(NULL, NULL) == -1);
    CHECK(br_debounce_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_debounce_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 257 && detector->version == 0 && !strcmp(detector->name, "Debounce"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Debounce is an email validation service that helps in reducing bounce rates by verifying email addresses. Debounce API keys can be used to access and validate email addresses."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "debounce"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    /* Pinned defaults comments out Debounce. Direct factory testing establishes
     * no positive CLI oracle or selector/default-registration parity. */
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 257, key, "key");
    CHECK(result->raw.len == 13 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 13 && !memcmp(json_object_get_string(part), key, 13));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = formatted_urls;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && formatted_urls == before);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const struct { const char *format; bool matches; } cases[] = {
        {"debounce '%s'", true}, {"DEBOUNCE=%s", true}, {"preDeBoUnCesuffix\r\n%s", true},
        {"debounce\r%s", true}, {"debounce\n%s", true}, {"debounce +%s/", true},
        {"%s", false}, {"%s debounce", false}, {"de bounce %s", false}, {"debounce%s", false},
        {"debounce x%s", false}, {"debounce _%s", false}, {"debounce %s_", false},
        {"debounce %s9", false}, {"debounce %.12s", false},
    };
    char input[192], changed[14];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char forbidden[] = "_-+./";
    for (size_t i = 0; i < sizeof(forbidden) - 1; ++i) {
        memcpy(changed, key1, sizeof(key1)); changed[6] = forbidden[i];
        snprintf(input, sizeof(input), "debounce %s", changed);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "debounce", 8); memset(input + 8, '.', gap); memcpy(input + 8 + gap, key1, 13);
        extraction_case(detector, input, 8 + gap + 13, gap == 40 ? key1 : NULL);
    }
    memset(changed, 'Z', 13); changed[13] = '\0';
    snprintf(input, sizeof(input), "debounce %s", changed);
    extraction_case(detector, input, strlen(input), changed); /* Mixed alnum, not hex; no entropy/FP filter. */
    snprintf(input, sizeof(input), "debounce %s %s", key1, key2);
    extraction_case(detector, input, strlen(input), key1); /* Whole matches do not overlap. */
    int n = snprintf(input, sizeof(input), "debounce%c%s", 0, key1);
    CHECK(n == 22); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\ndebounce %s\n\xff", key1);
    extraction_case(detector, input, (size_t)n, key1); /* No input-wide UTF-8 rejection. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *keys[3]; size_t count;
    const char *agent, *borrowed_url;
    char expected_url[67];
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t at = http->calls - 1;
    CHECK(at < expected->count && ctx && ctx->transport && !expected->borrowed_url);
    CHECK(!strcmp(request->method, "GET") && request->detector_type == 257);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(snprintf(expected->expected_url, sizeof(expected->expected_url), "https://api.debounce.io/v1/?api=%s&email=some@gmail.com", expected->keys[at]) == 66);
    CHECK(strlen(request->url) == 66 && !memcmp(request->url, expected->expected_url, 67));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, expected->agent)); /* No Type/Accept/Auth/Content-Length. */
    expected->borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 66 && !memcmp(expected->borrowed_url, expected->expected_url, 67));
        expected->borrowed_url = NULL; /* Complete stack URL stays live THROUGH release. */
    } else {
        CHECK(!response->status && !response->body.data && !response->body_error);
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "debounce %s\nDEBOUNCE %s\ndebounce %s", key1, key2, key1);
    expected_http expected = {.keys = {key1, key2, key1}, .count = 3, .agent = "TruffleHog debounce-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "debounce-offline"};
    for (int pass = 0; pass < 3; ++pass) {
        size_t before = formatted_urls;
        br_results results = test_scan(detector, &ctx, pass != 0, input, (size_t)n);
        CHECK(results.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        CHECK(formatted_urls == before + (pass ? 3u : 0u) && !expected.borrowed_url);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], pass != 0);
        br_results_clear(&results); http.calls = http.releases = 0;
    } /* Preserve duplicates and repeated scans; no verification cache. */
    size_t before = formatted_urls;
    br_results results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && formatted_urls == before + 3 && !http.calls && !http.releases);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3 && formatted_urls == before + 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false);
    br_results_clear(&results);
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "debounce %s", key1);
    expected_http expected = {.keys = {key1}, .count = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *body_error, *cause; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {204, 0, "ignored", NULL, true},
        {299, 0, "", NULL, true}, {300, 0, NULL, NULL, false}, {401, 0, "ignored", NULL, false},
        {500, 0, NULL, NULL, false}, {200, 1, NULL, "synthetic timeout", false},
        {200, -1, "ignored", "cannot format Debounce URL", false},
        {200, 1, NULL, "net/http: nil Context", false}, {204, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].body_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_url);
        check_result(&results.items[0], key1, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_allocation(void *user)
{
    (void)user; fail_alloc_size = sizeof(br_header); fail_alloc_after = 1; return false;
}

static void suppressed_setup(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "debounce %s", key1);
    expected_http expected = {.keys = {key1}, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport, .cancelled = fail_shared_allocation},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_alloc_after);
        check_result(&results.items[0], key1, false); br_results_clear(&results); http.releases = 0;
    }
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].secret_parts == prior->secret_parts && results->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void expect_failure(const br_detector *detector, const br_scan_ctx *ctx, br_slice data,
                            br_results *results, const br_result *prior, const char *cause)
{
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, data, results, &error) == -1 && error && !strcmp(error, cause));
    CHECK(!fail_alloc_after && !fail_part_after && !fail_format_after);
    check_prior(results, prior); free(error);
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "debounce %s\ndebounce %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    expected_http expected = {.keys = {key1, key2}, .count = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {0}; br_results results = {0};
    CHECK(br_finding_key(&sentinel, 777, "prior", "key") == 0);
    sentinel.verified = true; sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    CHECK(br_results_push(&results, &sentinel) == 0); br_result prior = results.items[0];
    size_t before = formatted_urls;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; /* Real regex failure returns +1. */
    expect_failure(detector, NULL, data, &results, &prior, "out of memory iterating regex");
    fail_alloc_size = 14; fail_alloc_after = 2;
    expect_failure(detector, NULL, data, &results, &prior, "out of memory copying detector capture");
    fail_part_after = 1;
    expect_failure(detector, NULL, data, &results, &prior, "cannot create Debounce result");
    CHECK(formatted_urls == before && !http.calls && !http.releases); /* Finding failure precedes prep/skip. */
    fail_alloc_size = 13; fail_alloc_after = 2;
    expect_failure(detector, NULL, data, &results, &prior, "cannot create Debounce result");
    CHECK(formatted_urls == before + 1 && !http.calls && !http.releases);
    fail_format_after = 1; truncate_format = false;
    expect_failure(detector, NULL, data, &results, &prior, "cannot format Debounce URL");
    CHECK(formatted_urls == before + 2 && !http.calls); /* Fatal BEFORE known nil-context skip. */
    fail_part_after = 2;
    expect_failure(detector, &ctx, data, &results, &prior, "cannot create Debounce result");
    CHECK(http.calls == 1 && http.releases == 1 && !expected.borrowed_url);
    http.calls = http.releases = 0;
    fail_format_after = 2; truncate_format = true;
    expect_failure(detector, &ctx, data, &results, &prior, "cannot format Debounce URL");
    CHECK(http.calls == 1 && http.releases == 1 && !expected.borrowed_url); /* Roll back earlier success. */
    http.calls = http.releases = 0;
    char *error = NULL; size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Debounce result"));
    results.cap = capacity; check_prior(&results, &prior); free(error);
    fail_format_after = 1; truncate_format = false;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_format_after);
    check_prior(&results, &prior);
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == 0);
    check_prior(&results, &prior); br_results_clear(&results);
    br_results recovered = test_scan(detector, &ctx, true, data.data, data.len);
    CHECK(recovered.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&recovered.items[0], key1, true); check_result(&recovered.items[1], key2, true);
    br_results_clear(&recovered);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    suppressed_setup(detector); resources_and_rollback(detector);
    return test_finish("Debounce direct factory: extraction, exact URL, SANE status-only verification and rollback");
}
