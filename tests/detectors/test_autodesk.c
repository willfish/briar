/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other_key[33], secret[17], other_secret[17];
typedef struct { const char *key, *secret; } expected_pair;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_autodesk_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 604 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Autodesk") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Autodesk provides software services for design and engineering. "
        "Autodesk API keys can be used to access and modify data within Autodesk services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "autodesk"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *patterns = detector->state;
    CHECK(br_autodesk_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == patterns);
    CHECK(br_autodesk_init(&again, NULL) == 0 && again == detector);
    CHECK(br_autodesk_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_autodesk_init(NULL, NULL) != 0);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair, bool verified)
{
    CHECK(result->detector_type == 604 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, pair.key, 32));
    CHECK(result->raw_v2.len == 48 && !memcmp(result->raw_v2.data, pair.key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair.secret, 16));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(result->verified == verified);
    CHECK(!result->verification_error && !result->redacted);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_pairs(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         const void *input, size_t len, const expected_pair *pairs,
                         size_t count, bool verified)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_pair(&results.items[i], pairs[i], verified);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed_key[33], changed_secret[17];
    expected_pair one = {key, secret};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"autodesk %s\nautodesk %s", 1},
        {"AUTODESK %s\r\nAUTODESK %s", 1},
        {"prefixAUTOdeskSuffix=%s\nautodesk %s", 1},
        {"autodesk %s %s", 1},
        {"autodesk %s\n%s", 1}, /* One prefix can reach both independent patterns. */
        {"%s\nautodesk %s", 0},
        {"%s %s autodesk", 0},
        {"autodesk %.31s\nautodesk %s", 0},
        {"autodesk %s\nautodesk %.15s", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, secret);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_pairs(detector, &ctx, false, input, (size_t)len, &one, cases[i].count, false);
    }
    expect_pairs(detector, &ctx, false, NULL, 0, NULL, 0, false);
    snprintf(input, sizeof(input), "autodesk %s", key);
    expect_pairs(detector, &ctx, true, input, strlen(input), NULL, 0, false);
    snprintf(input, sizeof(input), "autodesk %s", secret);
    expect_pairs(detector, &ctx, true, input, strlen(input), NULL, 0, false);
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s", secret, key);
    expect_pairs(detector, &ctx, false, input, strlen(input), &one, 1, false);
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"", "_"}, {"", "Q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "autodesk %s%s%s\nautodesk %s",
                 edges[i].before, key, edges[i].after, secret);
        expect_pairs(detector, &ctx, false, input, strlen(input), NULL, 0, false);
        snprintf(input, sizeof(input), "autodesk %s\nautodesk %s%s%s",
                 key, edges[i].before, secret, edges[i].after);
        expect_pairs(detector, &ctx, false, input, strlen(input), NULL, 0, false);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "autodesk");
        memset(input + at, '.', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\nautodesk %s", key, secret);
        expect_pairs(detector, &ctx, false, input, strlen(input), &one, gap == 40 ? 1 : 0, false);
        at = (size_t)snprintf(input, sizeof(input), "autodesk %s\nautodesk", key);
        memset(input + at, '.', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", secret);
        expect_pairs(detector, &ctx, false, input, strlen(input), &one, gap == 40 ? 1 : 0, false);
    }
    const char prefix[] = "autodesk";
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 32);
    size_t at = sizeof(prefix) + 32;
    int tail = snprintf(input + at, sizeof(input) - at, "\nautodesk %s", secret);
    CHECK(tail >= 0 && (size_t)tail < sizeof(input) - at);
    expect_pairs(detector, &ctx, false, input, at + (size_t)tail, &one, 1, false);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[10] = '+';
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s", changed_key, secret);
    expect_pairs(detector, &ctx, false, input, strlen(input), NULL, 0, false);
    memcpy(changed_secret, secret, sizeof(changed_secret));
    changed_secret[7] = '=';
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s", key, changed_secret);
    expect_pairs(detector, &ctx, false, input, strlen(input), NULL, 0, false);
    memset(changed_key, 'A', 32);
    changed_key[32] = '\0';
    memset(changed_secret, 'b', 16);
    changed_secret[16] = '\0';
    expected_pair low_entropy = {changed_key, changed_secret};
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s", changed_key, changed_secret);
    expect_pairs(detector, &ctx, false, input, strlen(input), &low_entropy, 1, false);
    at = (size_t)snprintf(input, sizeof(input), "autodesk %s", key);
    memset(input + at, '\n', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "autodesk %s", secret);
    expect_pairs(detector, &ctx, false, input, strlen(input), &one, 1, false);
    CHECK(!http.calls && !http.releases);
}

typedef struct { const expected_pair *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls); /* Previous responses are released immediately. */
    expected_pair pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://developer.api.autodesk.com/authentication/v1/authenticate"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 604);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    char payload[128];
    snprintf(payload, sizeof(payload), "grant_type=client_credentials&client_id=%s&client_secret=%s",
             pair.key, pair.secret);
    CHECK(request->body.len == strlen(payload));
    CHECK(request->body.data && !memcmp(request->body.data, payload, strlen(payload)));
    CHECK(request->nheaders == 2);
    size_t content_type = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Content-Type")) {
            ++content_type;
            CHECK(!strcmp(header->value, "application/x-www-form-urlencoded"));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog autodesk-test" : "TruffleHog"));
        } else CHECK(!"unexpected Autodesk request header");
    }
    CHECK(content_type == 1 && agent == 1);
}

static void test_occurrence_product(const br_detector *detector)
{
    const char *keys[] = {key, key, other_key};
    const char *secrets[] = {secret, other_secret, secret};
    expected_pair pairs[9];
    for (size_t k = 0; k < 3; ++k)
        for (size_t s = 0; s < 3; ++s) pairs[k * 3 + s] = (expected_pair){keys[k], secrets[s]};
    char input[512];
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s\nautodesk %s\n"
             "autodesk %s\nautodesk %s\nautodesk %s",
             keys[0], keys[1], keys[2], secrets[0], secrets[1], secrets[2]);
    expected_requests expected = {pairs, 9};
    test_http http = {.response = {.status = 204, .body_error = "ignored read failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_pairs(detector, &ctx, false, input, strlen(input), pairs, 9, false);
    CHECK(!http.calls && !http.releases);
    expect_pairs(detector, &ctx, true, input, strlen(input), pairs, 9, true);
    CHECK(http.calls == 9 && http.releases == 9);
}

static void test_verification(const br_detector *detector)
{
    char input[128], sensitive[128];
    snprintf(input, sizeof(input), "autodesk %s\nautodesk %s", key, secret);
    snprintf(sensitive, sizeof(sensitive), "synthetic key=%s secret=%s failed", key, secret);
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true},
        {204, 0, NULL, true}, {299, 0, NULL, true}, {300, 0, NULL, false},
        {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, NULL, false}, {200, 1, sensitive, false},
        {200, 1, "context canceled", false}, {204, 1, "context deadline exceeded", false},
    };
    expected_pair pair = {key, secret};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {&pair, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "autodesk-test"};
        expect_pairs(detector, &ctx, true, input, strlen(input), &pair, 1, cases[i].verified);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    /* ABI-only gap: unlike Go's nil-context request-creation skip, the native
     * transport failure is suppressed and leaves an unverified candidate. */
    expect_pairs(detector, NULL, true, input, strlen(input), &pair, 1, false);
    br_scan_ctx no_transport = {0};
    expect_pairs(detector, &no_transport, true, input, strlen(input), &pair, 1, false);
}

int main(void)
{
    test_secret(key, 32, 0);
    key[0] = 'K';
    key[31] = 'z';
    test_secret(other_key, 32, 9);
    other_key[0] = 'Q';
    test_secret(secret, 16, 0);
    secret[0] = 'S';
    secret[15] = 'Z';
    test_secret(other_secret, 16, 9);
    other_secret[0] = 'T';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrence_product(detector);
    test_verification(detector);
    return test_finish("Autodesk");
}
