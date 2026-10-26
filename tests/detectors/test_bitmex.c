/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char key[] = "AbCdEfGhIjKlMnOpQrStU_-9";
static const char other_key[] = "9-_UtSrQpOnMlKjIhGfEdCbA";
static const char secret[] = "AbCdEfGhIjKlMnOpQrStU_-9AbCdEfGhIjKlMnOpQrStU_-9";
static const char other_secret[] = "_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
/* Independent Python stdlib hmac.new(secret.encode('ascii'),
 * b'GET' + b'/api/v1/user' + b'1704164650' + b'', hashlib.sha256).hexdigest().
 * Frozen 2024-01-02T03:04:05Z, expiry five SECONDS later. Both inputs use _/-. */
static const char signature[] = "6b3b64625c3f2466791a2a78fd883b14276ab7acea02b89cf57634440ab8420c";
static const char other_signature[] = "0fdda0439a498040b59bd0af57b9a8fb5aa29429501ef65eaad476cde9e7dd5b";
static time_t frozen_time = (time_t)1704164645;
static bool fail_503_dup;

time_t time(time_t *out)
{
    if (out) *out = frozen_time;
    return frozen_time;
}

char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, "unexpected status code: 503")) {
        fail_503_dup = false; return NULL;
    }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

typedef struct { const char *key, *secret; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; } expected_requests;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 24 && strlen(other_key) == 24);
    CHECK(strlen(secret) == 48 && strlen(other_secret) == 48);
    CHECK(br_bitmex_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(!br_bitmex_init(&detector, &error) && detector && !error);
    CHECK(!br_bitmex_init(&again, NULL) && again == detector);
    CHECK(detector->type == 512 && detector->version == 0 && !strcmp(detector->name, "Bitmex"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Bitmex is a cryptocurrency exchange and derivative trading platform. Bitmex API keys can be used to access and trade on the platform programmatically."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bitmex"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair, bool verified, const char *error)
{
    CHECK(result->detector_type == 512 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 48 && !memcmp(result->raw.data, pair.secret, 48));
    CHECK(result->raw_v2.data && result->raw_v2.len == 72);
    CHECK(!memcmp(result->raw_v2.data, pair.key, 24) && !memcmp(result->raw_v2.data + 24, pair.secret, 48));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 24 && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 48 && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

/* Non-delimiter padding keeps fixture prefixes >40 bytes apart WITHOUT fixing
 * a deliberately absent trailing SPACE/CR/LF on the preceding token. */
static void combine(char *input, size_t capacity, const char *first, const char *second)
{
    size_t n = strlen(first), m = strlen(second);
    CHECK(n + 60 + m + 1 <= capacity);
    memcpy(input, first, n); memset(input + n, '|', 60); memcpy(input + n + 60, second, m + 1);
}

static void single_input(char *input, size_t capacity)
{
    char key_line[64], secret_line[80];
    snprintf(key_line, sizeof(key_line), "bitmex %s ", key);
    snprintf(secret_line, sizeof(secret_line), "bitmex %s ", secret);
    combine(input, capacity, key_line, secret_line);
}

static void expect_extract(const br_detector *detector, const char *input, const expected_pair *pairs, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_pair(&results.items[i], pairs[i], false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], key_line[128], secret_line[144];
    expected_pair pair = {key, secret};
    snprintf(secret_line, sizeof(secret_line), "bitmex %s ", secret);
    const struct { const char *format; bool valid; } key_cases[] = {
        {"bitmex %s ", true}, {"BITMEX\r\n%s\r\n", true}, {"prefixbitmexsuffix %s\n", true},
        {"bitmex\t%s ", false}, {"bitmex %s\t", false}, {"bitmex\v%s ", false},
        {"bitmex %s\f", false}, {"bitmex %s", false}, {"bitmex%s ", false},
        {"bitmex %.23s ", false}, {"bitmex %sx ", false},
    };
    for (size_t i = 0; i < sizeof(key_cases) / sizeof(key_cases[0]); ++i) {
        snprintf(key_line, sizeof(key_line), key_cases[i].format, key);
        combine(input, sizeof(input), key_line, secret_line);
        expect_extract(detector, input, &pair, key_cases[i].valid ? 1 : 0);
    }
    snprintf(key_line, sizeof(key_line), "bitmex %s ", key);
    const struct { const char *format; bool valid; } secret_cases[] = {
        {"BITMEX\n%s\r", true}, {"bitmex %s ", true}, {"bitmex\t%s ", false},
        {"bitmex %s\t", false}, {"bitmex %s\v", false}, {"bitmex\f%s ", false},
        {"bitmex %s", false}, {"bitmex%s ", false}, {"bitmex %.47s ", false}, {"bitmex %sx ", false},
    };
    for (size_t i = 0; i < sizeof(secret_cases) / sizeof(secret_cases[0]); ++i) {
        snprintf(secret_line, sizeof(secret_line), secret_cases[i].format, secret);
        combine(input, sizeof(input), key_line, secret_line);
        expect_extract(detector, input, &pair, secret_cases[i].valid ? 1 : 0);
    }
    snprintf(secret_line, sizeof(secret_line), "bitmex %s ", secret);
    snprintf(key_line, sizeof(key_line), "bitmex bitmex %s ", key);
    combine(input, sizeof(input), key_line, secret_line);
    expect_extract(detector, input, &pair, 1); /* Consuming full match prevents rescanning its second prefix. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(key_line, "bitmex", 6); memset(key_line + 6, '.', gap);
        snprintf(key_line + 6 + gap, sizeof(key_line) - 6 - gap, " %s ", key);
        combine(input, sizeof(input), key_line, secret_line);
        expect_extract(detector, input, &pair, gap == 40 ? 1 : 0);
    }
    char low_key[25], low_secret[49];
    memset(low_key, 'A', 24); low_key[24] = '\0';
    memset(low_secret, '_', 48); low_secret[48] = '\0';
    snprintf(key_line, sizeof(key_line), "bitmex %s ", low_key);
    snprintf(secret_line, sizeof(secret_line), "bitmex %s ", low_secret);
    combine(input, sizeof(input), key_line, secret_line);
    expected_pair low_pair = {low_key, low_secret};
    expect_extract(detector, input, &low_pair, 1); /* No entropy filter. */
    snprintf(input, sizeof(input), "bitmex %s ", key);
    expect_extract(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "bitmex %s ", secret);
    expect_extract(detector, input, NULL, 0);
    expect_extract(detector, "", NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    expected_pair pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.bitmex.com/api/v1/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 512);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4); /* No Content-Type, Accept or manual Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "api-expires") && !strcmp(request->headers[0].value, "1704164650"));
    CHECK(!strcmp(request->headers[1].name, "api-key") && !strcmp(request->headers[1].value, pair.key));
    CHECK(!strcmp(request->headers[2].name, "api-signature"));
    const char *golden = NULL;
    if (!strcmp(pair.secret, secret)) golden = signature;
    else if (!strcmp(pair.secret, other_secret)) golden = other_signature;
    CHECK(golden && strlen(request->headers[2].value) == 64 && !strcmp(request->headers[2].value, golden));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog bitmex-test"));
}

static void add_record(char *input, size_t capacity, size_t *at, const char *value)
{
    int n = snprintf(input + *at, capacity - *at, "bitmex %s ", value);
    CHECK(n >= 0 && (size_t)n + 61 < capacity - *at);
    *at += (size_t)n; memset(input + *at, '|', 60); *at += 60; input[*at] = '\0';
}

static void occurrences_and_goldens(const br_detector *detector)
{
    char input[1024]; size_t at = 0;
    const char *keys[] = {key, other_key, key}, *secrets[] = {secret, other_secret, secret};
    for (size_t i = 0; i < 3; ++i) add_record(input, sizeof(input), &at, keys[i]);
    for (size_t i = 0; i < 3; ++i) add_record(input, sizeof(input), &at, secrets[i]);
    expected_pair pairs[9];
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) pairs[k * 3 + s] = (expected_pair){keys[k], secrets[s]};
    expected_requests expected = {pairs, 9};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitmex-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 9 && http.calls == (verify ? 9 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) check_pair(&results.items[i], pairs[i], verify, NULL);
        br_results_clear(&results);
    } /* Both independent HMAC goldens; no deduplication, entropy gate or success break. */
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[256]; single_input(input, sizeof(input));
    expected_pair pair = {key, secret}; expected_requests expected = {&pair, 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitmex-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_pair(&results.items[0], pair, verified, error);
    br_results_clear(&results);
}

static void status_and_errors(const br_detector *detector)
{
    const int statuses[] = {200, 401, 201, 204, 299, 403, 302, 500};
    static const unsigned char body[] = {0, 0xff, '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"}};
        verify_case(detector, &http, i == 0, i < 2 ? NULL : error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = "lookup: no such host"};
    verify_case(detector, &http, false, http.send_error);
    verify_case(detector, &http, false, http.send_error);
    http.send_error = NULL;
    verify_case(detector, &http, false, "HTTP transport failed");
    char echoed[256]; snprintf(echoed, sizeof(echoed), "key=%s secret=%s again=%s", key, secret, secret);
    http.send_error = echoed;
    verify_case(detector, &http, false, echoed); /* Deliberately UNREDACTED, exactly like upstream. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[256]; single_input(input, sizeof(input));
    expected_pair pair = {key, secret};
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], pair, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], pair, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_pair(&results.items[0], pair, false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
    expected_requests expected = {&pair, 1};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitmex-test"};
    char *error = NULL;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "could not sign or record Bitmex verification"));
    CHECK(!fail_503_dup && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, &http, false, "unexpected status code: 503");
    frozen_time = (time_t)INT64_MAX;
    http = (test_http){.response = {.status = 200}}; error = NULL;
    rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !results.len && !http.calls && !http.releases);
    free(error); br_results_clear(&results);
    frozen_time = (time_t)1704164645;
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences_and_goldens(detector);
    status_and_errors(detector);
    context_and_resource(detector);
    return test_finish("Bitmex");
}
