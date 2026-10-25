/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Deliberately include g-z: upstream accepts lowercase alnum, not just UUID hex. */
static const char key[] = "g7h8j9k0-m1n2-p3q4-r5s6-t7u8v9w0x1y2";
static const char organization[] = "z9y8x7w6-v5u4-t3s2-r1q0-p9n8m7k6j5h4";
static const char other_organization[] = "b7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3";
typedef struct { const char *key, *organization; } expected_pair;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_anypoint_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_anypoint_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_anypoint_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 179 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Anypoint") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Anypoint is a unified platform that allows organizations to build and manage APIs and integrations. "
        "Anypoint credentials can be used to access and manipulate these integrations and API data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "anypoint"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(strcmp(pair.key, pair.organization) != 0);
    CHECK(result->detector_type == 179 && !result->detector_name);
    CHECK(result->raw.len == 36 && !memcmp(result->raw.data, pair.key, 36));
    CHECK(result->raw_v2.len == 72 && !memcmp(result->raw_v2.data, pair.key, 36));
    CHECK(!memcmp(result->raw_v2.data + 36, pair.organization, 36));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "organization", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.organization));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        CHECK(results.items[i].raw.len == 36 && results.items[i].raw_v2.len == 72);
        size_t p = 0;
        for (; p < count; ++p)
            if (!memcmp(results.items[i].raw.data, pairs[p].key, 36) &&
                !memcmp(results.items[i].raw_v2.data + 36, pairs[p].organization, 36)) break;
        CHECK(p < count);
        check_pair(&results.items[i], pairs[p]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        /* Source map order is unspecified; require unique pair identities instead. */
        for (size_t j = 0; j < i; ++j) CHECK(memcmp(results.items[i].raw_v2.data, results.items[j].raw_v2.data, 72) != 0);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed[37];
    const expected_pair one[] = {{key, organization}};
    snprintf(input, sizeof(input), "%s\norg %s", key, organization);
    expect_extraction(detector, input, one, 1); /* Direct scan needs no dispatch keyword. */
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "anypoint %s %s", key, organization);
    expect_extraction(detector, input, NULL, 0); /* anypoint is not the organization prefix. */
    snprintf(input, sizeof(input), "org %s", organization);
    expect_extraction(detector, input, NULL, 0); /* The only possible pair is equal. */
    snprintf(input, sizeof(input), "org %s\norg %s", key, organization);
    const expected_pair directed[] = {{key, organization}, {organization, key}};
    expect_extraction(detector, input, directed, 2);
    snprintf(input, sizeof(input), "preORGsuffix:%s\n%s", organization, key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "ORGANIZATION=%s\n%s", organization, key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "org\r\n%s\n%s", organization, key);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "org");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\n%s", organization, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"", "_"}, {"", "q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s%s\norg %s", edges[i].before, key, edges[i].after, organization);
        expect_extraction(detector, input, NULL, 0);
        snprintf(input, sizeof(input), "%s\norg %s%s%s", key, edges[i].before, organization, edges[i].after);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[0] = 'G';
    snprintf(input, sizeof(input), "%s\norg %s", changed, organization);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, organization, sizeof(changed));
    changed[0] = 'Z';
    snprintf(input, sizeof(input), "%s\norg %s", key, changed);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[8] = 'x';
    snprintf(input, sizeof(input), "%s\norg %s", changed, organization);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%.35s\norg %s", key, organization);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%s\norg %s\n%s\norg %s", key, organization, key, organization);
    expect_extraction(detector, input, one, 1);
    const expected_pair low[] = {{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"}};
    snprintf(input, sizeof(input), "%s\norg %s", low[0].key, low[0].organization);
    expect_extraction(detector, input, low, 1);
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\norg %s", organization);
    expect_extraction(detector, input, one, 1); /* Span limits are engine-owned. */
}

typedef struct { const expected_pair *pairs; size_t count; unsigned seen; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 179);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog anypoint-test"));
    CHECK(expected->count <= 4);
    size_t p = 0;
    for (; p < expected->count; ++p) {
        char url[192], auth[44];
        snprintf(url, sizeof(url),
                 "https://anypoint.mulesoft.com/apiplatform/repository/v2/organizations/%s/apis/by-name?apiName=",
                 expected->pairs[p].organization);
        snprintf(auth, sizeof(auth), "Bearer %s", expected->pairs[p].key);
        if (!strcmp(request->url, url) && !strcmp(request->headers[1].value, auth)) break;
    }
    CHECK(p < expected->count && !(expected->seen & (1u << p)));
    expected->seen |= 1u << p;
}

static void verification(const br_detector *detector)
{
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    const expected_pair pair = {key, organization};
    char input[256];
    snprintf(input, sizeof(input), "%s\norg %s\n%s\norg %s", key, organization, key, organization);
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {&pair, 1, 0};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body-read/drain error"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "anypoint-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen == 1);
        check_pair(&results.items[0], pair);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_pair(&results.items[0], pair);
    br_results_clear(&results);
}

static void unequal_product(const br_detector *detector)
{
    char input[512], cause[256];
    snprintf(input, sizeof(input), "%s\norg %s\norg %s\n%s\norg %s\norg %s",
             key, organization, other_organization, key, organization, other_organization);
    const expected_pair pairs[] = {
        {key, organization}, {key, other_organization},
        {organization, other_organization}, {other_organization, organization},
    };
    expect_extraction(detector, input, pairs, 4);
    snprintf(cause, sizeof(cause), "key=%s organization=%s repeated=%s", key, organization, key);
    static const unsigned char body[] = "not JSON";
    for (int mode = 0; mode < 2; ++mode) {
        requests expected = {pairs, 4, 0};
        test_http http = {
            .response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = "ignored"},
            .send_rc = mode ? -1 : 0, .send_error = mode ? cause : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "anypoint-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 4 && http.releases == 4 && expected.seen == 15);
        for (size_t i = 0; i < results.len; ++i) {
            CHECK(results.items[i].verified == (mode == 0));
            if (mode) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, cause));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "org %s", organization);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key) == 36 && strlen(organization) == 36 && strlen(other_organization) == 36);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unequal_product(detector);
    return test_finish("Anypoint");
}
