/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[41], other[41];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* Target only the core setter's positive-1 allocation failure. */
char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

typedef struct {
    const char *const *keys;
    size_t count;
    uint32_t timeout_limit;
    const int *statuses;
} expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_buddyns_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 598 && detector->version == 0);
    CHECK(!strcmp(detector->name, "BuddyNS") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "BuddyNS is a DNS hosting service. BuddyNS API keys can be used to manage DNS zones and records."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "buddyns"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_buddyns_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_buddyns_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_buddyns_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_buddyns_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                               const void *input, size_t len, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 598, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[41];
    const char *one[] = {key};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"buddyns = '%s'", 1}, {"BUDDYNS: %s", 1}, {"preBuDdYnSsuffix=%s", 1},
        {"%s", 0}, {"%s buddyns", 0}, {"buddyns%s", 0},
        {"buddyns _%s", 0}, {"buddyns %s_", 0}, {"buddyns %s9", 0},
        {"buddyns %.39s", 0}, {"buddyns\r\n%s", 1}, {"buddyns %s=", 1},
        {"buddyns %s %s", 1}, /* A later occurrence needs a fresh keyword prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, key, other);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)n, one, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    memcpy(changed, key, sizeof(key));
    changed[10] = 'A';
    snprintf(input, sizeof(input), "BUDDYNS %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0); /* CI is scoped to the provider, not the capture. */
    changed[10] = '-';
    snprintf(input, sizeof(input), "buddyns %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memset(changed, 'z', 40); changed[40] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "buddyns %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), low_entropy, 1); /* Lowercase alnum, not hex or entropy-filtered. */
    const char prefix[] = "buddyns";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, key, sizeof(key));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, sizeof(key) - 1);
    expect_extraction(detector, &ctx, input, sizeof(prefix) + sizeof(key) - 1, one, 1);
    CHECK(!http.calls && !http.releases);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const char *expected_key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.buddyns.com/api/v2/zone/"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 598);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    size_t json = 0, auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Content-Type")) {
            ++json; CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "Authorization")) {
            ++auth; CHECK(!strncmp(header->value, "Token ", 6) && !strcmp(header->value + 6, expected_key));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog buddyns-test" : "TruffleHog"));
        } else CHECK(!"unexpected BuddyNS header (no Accept, Content-Length, Bearer or Basic)");
    }
    CHECK(json == 1 && auth == 1 && agent == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *value, bool verified, const char *error)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "buddyns %s", value);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n);
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 598, value, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
        if (strstr(error, value)) CHECK(strstr(results.items[0].verification_error, value) && !strstr(results.items[0].verification_error, "[REDACTED]"));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_occurrences(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "buddyns %s\nbuddyns %s\nbuddyns %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_requests expected = {.keys = keys, .count = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored body/read/drain error"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_extraction(detector, &ctx, input, strlen(input), keys, 3);
    CHECK(!http.calls && !http.releases);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 598, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_status_and_unredacted_errors(const br_detector *detector)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {403, false, "unexpected status code: 403"},
        {429, false, "unexpected status code: 429"}, {503, false, status_503},
    };
    static const unsigned char body[] = "\xff\0not JSON";
    const char *keys[] = {key};
    expected_requests expected = {.keys = keys, .count = 1};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body) - 1}, .body_error = "ignored body/read/drain/close error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "buddyns-test"};
        expect_one(detector, &ctx, true, key, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, key, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char echoed[160];
    snprintf(echoed, sizeof(echoed), "synthetic key=%s Authorization=Token %s rejected", key, key);
    const char *causes[] = {
        echoed, "lookup synthetic: no such host", "context canceled", "context deadline exceeded",
        "unsupported: synthetic SANE transport", NULL,
    };
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = "must not replace transport cause"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = causes[i], .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, key, false, causes[i] ? causes[i] : "HTTP transport failed");
        CHECK(http.calls == 1 && http.releases == 1);
        http.calls = http.releases = 0; http.send_error = NULL; http.send_rc = 0;
        expect_one(detector, &ctx, true, key, true, NULL); /* Errors never cache or suppress later findings. */
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *keys[] = {other};
    expected_requests expected = {.keys = keys, .count = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, other, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, other, false, "context deadline exceeded");
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 0; ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, other, false, "context canceled");
    CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, other, false, NULL);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL; http.calls = http.releases = 0; expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, other, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    expect_one(detector, NULL, true, key, false, "net/http: nil Context");
    expect_one(detector, NULL, false, key, false, NULL);
    br_scan_ctx missing_transport = {0};
    expect_one(detector, &missing_transport, true, key, false, "HTTP transport not installed");
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_positive_setter_failure_rollback(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "buddyns %s\nbuddyns %s", key, other);
    const char *keys[] = {key, other};
    const int statuses[] = {200, 503};
    expected_requests expected = {.keys = keys, .count = 2, .statuses = statuses};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && *error);
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    test_key_result(&results.items[0], 598, key, "key");
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    test_key_result(&results.items[1], 598, other, "key");
    CHECK(!results.items[1].verified && results.items[1].verification_error && !strcmp(results.items[1].verification_error, status_503));
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 40, 0); test_secret(other, 40, 11);
    key[39] = 'z'; other[39] = 'g'; /* Valid letters outside hexadecimal. */
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_status_and_unredacted_errors(detector);
    test_context_and_creation(detector);
    test_positive_setter_failure_rollback(detector);
    return test_finish("BuddyNS lowercase alnum occurrences + Token auth + unredacted errors");
}
