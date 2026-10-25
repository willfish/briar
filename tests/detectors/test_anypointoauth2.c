/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic fixtures only: the real POST endpoint creates token state. */
static const char id[] = "0123456789abcdef0123456789abcdef";
static const char other_id[] = "fedcba9876543210fedcba9876543210";
static const char secret[] = "0123456789ABCDef0123456789ABCDef";
static const char other_secret[] = "FEDCba9876543210FEDCba9876543210";
typedef struct { const char *id, *secret; } expected_pair;

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 1032 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, pair.secret, 32));
    CHECK(result->raw_v2.len == 65 && !memcmp(result->raw_v2.data, pair.id, 32));
    CHECK(result->raw_v2.data[32] == ':' && !memcmp(result->raw_v2.data + 33, pair.secret, 32));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.id));
    CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_anypointoauth2_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_anypointoauth2_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1032 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AnypointOAuth2") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Anypoint is a unified platform that allows organizations to build and manage "
                  "APIs and integrations. Anypoint credentials can be used to access and "
                  "manipulate these integrations and API data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "anypoint"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_anypointoauth2_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_anypointoauth2_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    /* Both upstream collections are maps: compare unique pairs without requiring map order. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results.len; ++j) {
            const br_result *candidate = &results.items[j];
            if (candidate->raw_v2.len == 65 && !memcmp(candidate->raw_v2.data, pairs[i].id, 32) &&
                !memcmp(candidate->raw_v2.data + 33, pairs[i].secret, 32)) {
                CHECK(!result);
                result = candidate;
            }
        }
        CHECK(result);
        check_pair(result, pairs[i]);
        CHECK(!result->verified && !result->verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed[33];
    const expected_pair one[] = {{id, secret}};
    /* Direct calls accept id/secret prefixes without the engine keyword anypoint. */
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, secret);
    CHECK(!strstr(input, "anypoint"));
    expect_extraction(detector, input, strlen(input), one, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
    const struct { const char *format; bool matches; } cases[] = {
        {"anypoint %s\nsecret %s", true},
        {"id %s\nanypoint %s", true},
        {"anypoint %s\nanypoint %s", true},
        {"preIDstuff:%s\npreSECRETstuff:%s", true},
        {"id '%s'\nsecret '%s'", true},
        {"id\r\n%s\nsecret\r\n%s", true},
        {"id \xc3\xa9%s\xc3\xa9\nsecret %s", true},
        {"%s\n%s", false}, {"id %s\n%s", false}, {"%s\nsecret %s", false},
        {"id%s\nsecret %s", false}, {"id %s\nsecret%s", false},
        {"id _%s\nsecret %s", false}, {"id %s_\nsecret %s", false},
        {"id %s\nsecret _%s", false}, {"id %s\nsecret %s_", false},
        {"id %sf\nsecret %s", false}, {"id %s\nsecret %sF", false},
        {"id %.31s\nsecret %s", false}, {"id %s\nsecret %.31s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, id, secret);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "id", 2);
        memset(input + 2, '-', gap);
        snprintf(input + 2 + gap, sizeof(input) - 2 - gap, "%s\nsecret %s", id, secret);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 2, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "id %s\nsecret", id);
        memset(input + at, '-', gap);
        memcpy(input + at + gap, secret, sizeof(secret));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(changed, id, sizeof(changed));
    changed[0] = 'A';
    snprintf(input, sizeof(input), "ID %s\nsecret %s", changed, secret);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    const char invalid[] = {'g', 'G', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, secret, sizeof(changed));
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "id %s\nsecret %s", id, changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const expected_pair low[] = {{changed, secret}};
    snprintf(input, sizeof(input), "id %s\nsecret %s", changed, secret);
    expect_extraction(detector, input, strlen(input), low, 1);

    snprintf(input, sizeof(input), "id %s\nid %s\nid %s\nsecret %s\nsecret %s\nsecret %s",
             id, other_id, id, secret, other_secret, secret);
    const expected_pair product[] = {{id, secret}, {id, other_secret}, {other_id, secret}, {other_id, other_secret}};
    expect_extraction(detector, input, strlen(input), product, 4);
    snprintf(input, sizeof(input), "anypoint %s\nanypoint %s\nanypoint %s", id, other_id, id);
    const expected_pair unequal[] = {{id, other_id}, {other_id, id}};
    expect_extraction(detector, input, strlen(input), unequal, 2);
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, id);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "id %s %s\nsecret %s %s", id, other_id, secret, other_secret);
    expect_extraction(detector, input, strlen(input), one, 1);

    size_t at = (size_t)snprintf(input, sizeof(input), "id %s\n", id);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\nsecret %s", secret);
    expect_extraction(detector, input, strlen(input), one, 1); /* Engine owns the credential span limit. */
    memcpy(input, "id\0", 3);
    at = 3 + (size_t)snprintf(input + 3, sizeof(input) - 3, "%s\nsecret %s", id, secret);
    expect_extraction(detector, input, at, one, 1);
}

typedef struct {
    const expected_pair *pairs;
    size_t count;
    const int *statuses;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    size_t index = http->calls - 1;
    expected_pair pair = expected->pairs[index];
    char body[160];
    snprintf(body, sizeof(body), "{\"grant_type\":\"client_credentials\",\"client_id\":\"%s\",\"client_secret\":\"%s\"}",
             pair.id, pair.secret);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://anypoint.mulesoft.com/accounts/oauth2/token"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, strlen(body)));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1032);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog anypoint-test"));
    if (expected->statuses) http->response.status = expected->statuses[index];
}

static void test_verification(const br_detector *detector)
{
    char input[256], cause[192];
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, secret);
    snprintf(cause, sizeof(cause), "id=%s secret=%s repeated=%s", id, secret, secret);
    const expected_pair one[] = {{id, secret}};
    expected_requests expected = {one, 1, NULL};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL}, {422, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context canceled", false, "context canceled"},
        {422, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, NULL, false, "HTTP transport failed"},
        {200, -1, cause, false, cause}, /* Neither ID nor secret is redacted upstream. */
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body-read failure"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "anypoint-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_pair(&results.items[0], one[0]);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, id);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, secret);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_pair(&results.items[0], one[0]);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void test_success_deletion(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "id %s\nid %s\nid %s\nsecret %s\nsecret %s\nsecret %s",
             id, other_id, id, secret, other_secret, secret);
    /* This implementation uses first-occurrence traversal; Go map order is unspecified. */
    const expected_pair consumed[] = {{id, secret}, {other_id, other_secret}};
    const int success_statuses[] = {200, 422};
    for (size_t i = 0; i < sizeof(success_statuses) / sizeof(success_statuses[0]); ++i) {
        const int statuses[] = {success_statuses[i], 401};
        expected_requests expected = {consumed, 2, statuses};
        test_http http = {.response = {.body_error = "ignored body-read failure"},
                           .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "anypoint-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        check_pair(&results.items[0], consumed[0]);
        CHECK(results.items[0].verified && !results.items[0].verification_error);
        check_pair(&results.items[1], consumed[1]);
        CHECK(!results.items[1].verified && !results.items[1].verification_error);
        br_results_clear(&results);
    }

    /* An invalid secret stays available for later IDs; the successful second
     * secret is deleted, and a new scan starts with fresh local collections. */
    const expected_pair retry[] = {{id, secret}, {id, other_secret}, {other_id, secret}};
    const int statuses[] = {401, 422, 401};
    expected_requests expected = {retry, 3, statuses};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "anypoint-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], retry[i]);
        CHECK(results.items[i].verified == (i == 1) && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    const expected_pair all[] = {{id, secret}, {id, other_secret}, {other_id, secret}, {other_id, other_secret}};
    expected = (expected_requests){all, 4, NULL};
    http = (test_http){.response = {.status = 500}, .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], all[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "unexpected status code: 500"));
    }
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *state = detector->state;
    CHECK(strlen(id) == 32 && strlen(other_id) == 32 && strlen(secret) == 32 && strlen(other_secret) == 32);
    test_extraction(detector);
    test_verification(detector);
    test_success_deletion(detector);
    const br_detector *again = NULL;
    CHECK(br_anypointoauth2_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("AnypointOAuth2");
}
