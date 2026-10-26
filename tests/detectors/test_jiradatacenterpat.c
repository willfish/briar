/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/datacenter.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char token[45], other_token[45];
static const char no_url_message[] =
    "No Jira Data Center URL was found or configured. To verify this token, "
    "set the Jira instance base URL as a custom endpoint.";

typedef struct {
    const char *token, *url;
    bool verified;
    const char *error, *name, *email;
} expected_result;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_jiradatacenterpat_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 1046 && detector->version == 0);
    CHECK(!strcmp(detector->name, "JiraDataCenterPAT") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Jira Data Center is a self-hosted version of Jira. Personal Access Tokens "
        "(PATs) are used to authenticate API requests to Jira Data Center instances."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "jira") &&
          !strcmp(detector->keywords[1], "atlassian"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->cloud_endpoint);
    CHECK(detector->validate_endpoints == br_endpoints_validate_configured);
    const void *patterns = detector->state;
    CHECK(br_jiradatacenterpat_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == patterns);
    CHECK(br_jiradatacenterpat_init(&again, NULL) == 0 && again == detector);
    CHECK(br_jiradatacenterpat_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_jiradatacenterpat_init(NULL, NULL) != 0);
    return detector;
}

static void check_string(br_json *object, const char *field, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, field, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK(!strcmp(json_object_get_string(value), expected));
}

static bool matches(const br_result *result, const expected_result *expected)
{
    if (result->raw.len != 44 || memcmp(result->raw.data, expected->token, 44)) return false;
    if (!expected->url) return !result->raw_v2.data && !result->raw_v2.len;
    size_t len = strlen(expected->url);
    return result->raw_v2.len == 45 + len && !memcmp(result->raw_v2.data, expected->token, 44) &&
           result->raw_v2.data[44] == ':' && !memcmp(result->raw_v2.data + 45, expected->url, len);
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 1046 && !result->detector_name);
    CHECK(matches(result, expected));
    char redacted[10];
    snprintf(redacted, sizeof(redacted), "%.3s...%.3s", expected->token, expected->token + 41);
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (expected->url ? 2 : 1));
    check_string(result->secret_parts, "token", expected->token);
    if (expected->url) check_string(result->secret_parts, "url", expected->url);
    else {
        br_json *unused = NULL;
        CHECK(!json_object_object_get_ex(result->secret_parts, "url", &unused));
    }
    CHECK(result->verified == expected->verified);
    if (expected->error) {
        CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
        CHECK(!strstr(result->verification_error, expected->token));
    } else CHECK(!result->verification_error);
    if (!expected->url) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        check_string(result->extra_data, "message", no_url_message);
    } else if (expected->verified) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) ==
              1 + (expected->name != NULL) + (expected->email != NULL));
        check_string(result->extra_data, "endpoint", expected->url);
        if (expected->name) check_string(result->extra_data, "display_name", expected->name);
        if (expected->email) check_string(result->extra_data, "email_address", expected->email);
    } else CHECK(!result->extra_data);
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const void *input, size_t len, const expected_result *expected, size_t count)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(count <= 8 && results.len == count);
    unsigned seen = 0;
    for (size_t i = 0; i < results.len; ++i) {
        size_t e = 0;
        for (; e < count; ++e) if (matches(&results.items[i], &expected[e])) break;
        CHECK(e < count && !(seen & (1u << e)));
        seen |= 1u << e;
        check_result(&results.items[i], &expected[e]);
    }
    CHECK(seen == (1u << count) - 1);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[45];
    expected_result one = {.token = token};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"jira %s", 1}, {"ATLASSIAN = '%s'", 1}, {"prefixJIRAsuffix=%s", 1},
        {"%s", 0}, {"%s jira", 0}, {"jira _%s", 0}, {"jira %.43s", 0},
        {"jira %s=", 0}, {"jira %sA", 0}, {"jira %s+", 0}, {"jira %s/", 0},
        {"jira %s_", 1}, {"jira\r\n%s", 1},
        {"jira %s\njira %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, token, token);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_results(detector, &ctx, false, input, (size_t)len, &one, cases[i].count);
    }
    expect_results(detector, &ctx, true, "", 0, NULL, 0);
    const char prefix[] = "jira";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, token, sizeof(token));
        expect_results(detector, &ctx, false, input, strlen(input), &one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), token, 44);
    expect_results(detector, &ctx, false, input, sizeof(prefix) + 44, &one, 1);
    snprintf(input, sizeof(input), "jira %s", token);
    expect_results(detector, &ctx, true, input, strlen(input), &one, 1); /* No URL: no HTTP. */

    unsigned char raw[33];
    memset(raw, '7', sizeof(raw));
    CHECK(EVP_EncodeBlock((unsigned char *)changed, raw, sizeof(raw)) == 44);
    snprintf(input, sizeof(input), "jira %s", changed);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0); /* Missing decoded colon. */
    raw[1] = ':'; /* Structural validation does not require a twelve-digit ID. */
    CHECK(EVP_EncodeBlock((unsigned char *)changed, raw, sizeof(raw)) == 44);
    one.token = changed;
    snprintf(input, sizeof(input), "atlassian %s", changed);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1);
    snprintf(input, sizeof(input), "jira %s\natlassian %s\njira %s", token, other_token, token);
    const expected_result two[] = {{.token = token}, {.token = other_token}};
    expect_results(detector, &ctx, false, input, strlen(input), two, 2);
    CHECK(!http.calls && !http.releases);
}

static void test_endpoints(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "jira %s\natlassian https://found.invalid:8443/path?old=1\n"
             "jira https://found.invalid:8443/", token);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expected_result found = {.token = token, .url = "https://found.invalid:8443"};
    expect_results(detector, &ctx, false, input, strlen(input), &found, 1);
    expect_results(detector, NULL, false, input, strlen(input), &found, 1);
    br_endpoints endpoints = {0};
    ctx.endpoints = &endpoints;
    expected_result fallback = {.token = token};
    expect_results(detector, &ctx, true, input, strlen(input), &fallback, 1);
    endpoints.use_found = true;
    expect_results(detector, &ctx, false, input, strlen(input), &found, 1);
    const char *configured[] = {"https://configured.invalid///", "https://configured.invalid",
                                "https://found.invalid:8443/"};
    endpoints.configured = configured;
    endpoints.nconfigured = 3;
    const expected_result pairs[] = {
        {.token = token, .url = "https://configured.invalid"},
        {.token = token, .url = "https://found.invalid:8443"},
    };
    expect_results(detector, &ctx, false, input, strlen(input), pairs, 2);
    endpoints.use_found = false;
    expect_results(detector, &ctx, false, input, strlen(input), pairs, 2);
    const char *empty[] = {"", "///"};
    endpoints = (br_endpoints){.configured = empty, .nconfigured = 2};
    expected_result empty_url = {.token = token, .url = ""};
    expect_results(detector, &ctx, false, input, strlen(input), &empty_url, 1);
    CHECK(!http.calls && !http.releases);
}

typedef struct { const char *token, *url; int status; } expected_request;
typedef struct { const expected_request *items; size_t count; unsigned seen; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(expected->count <= 8 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 1046);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    const char *authorization = NULL;
    size_t accept = 0, auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Accept")) {
            ++accept;
            CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "Authorization")) {
            ++auth;
            authorization = header->value;
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog jira-pat-test" : "TruffleHog"));
        } else CHECK(!"unexpected Jira PAT request header");
    }
    CHECK(accept == 1 && auth == 1 && agent == 1 && authorization);
    size_t e = 0;
    for (; e < expected->count; ++e) {
        char bearer[52];
        snprintf(bearer, sizeof(bearer), "Bearer %s", expected->items[e].token);
        if (!strcmp(request->url, expected->items[e].url) && !strcmp(authorization, bearer)) break;
    }
    CHECK(e < expected->count && !(expected->seen & (1u << e)));
    expected->seen |= 1u << e;
    if (expected->items[e].status) http->response.status = expected->items[e].status;
}

static void test_verification(const br_detector *detector)
{
    const char *list[] = {"https://jira-check.invalid/old?discard=1"};
    br_endpoints endpoints = {.configured = list, .nconfigured = 1};
    char input[64], sensitive[256], redacted[192];
    snprintf(input, sizeof(input), "jira %s", token);
    snprintf(sensitive, sizeof(sensitive), "endpoint=%s token=%s again=%s", list[0], token, token);
    snprintf(redacted, sizeof(redacted), "endpoint=%s token=[REDACTED] again=[REDACTED]", list[0]);
    const struct {
        int status;
        const char *body, *read_error;
        int send_rc;
        const char *send_error;
        bool verified;
        const char *error, *name, *email;
    } cases[] = {
        {.status = 200, .body = "{\"displayName\":\"Synthetic User\",\"emailAddress\":\"user@example.invalid\"}",
         .verified = true, .name = "Synthetic User", .email = "user@example.invalid"},
        {.status = 200, .body = "{\"displayName\":\"\",\"emailAddress\":\"\"}",
         .verified = true, .name = "", .email = ""},
        {.status = 200, .body = "{\"displayname\":\"wrong\",\"EmailAddress\":\"wrong\"}", .verified = true},
        {.status = 200, .body = "{\"displayName\":42,\"emailAddress\":[\"wrong\"]}", .verified = true},
        {.status = 200, .body = "{\"displayName\":\"old\",\"displayName\":\"last\",\"emailAddress\":\"old\",\"emailAddress\":null} trailing",
         .verified = true, .name = "last"},
        {.status = 200, .body = "{\"displayName\":null,\"displayName\":\"\",\"emailAddress\":\"first\"} {\"emailAddress\":\"ignored\"}",
         .verified = true, .name = "", .email = "first"},
        {.status = 200, .body = "[]", .verified = true},
        {.status = 200, .body = "not JSON", .verified = true},
        {.status = 200, .body = "{", .read_error = sensitive, .verified = true},
        {.status = 200, .body = "{}", .read_error = sensitive, .verified = true},
        {.status = 200, .body = "", .read_error = sensitive, .verified = true},
        {.status = 401, .body = "{}", .read_error = sensitive},
        {.status = 403, .body = "{}", .read_error = sensitive, .error = "unexpected HTTP response status 403"},
        {.status = 500, .body = "{}", .error = "unexpected HTTP response status 500"},
        {.status = 200, .body = "{}", .send_rc = 1, .send_error = sensitive, .error = redacted},
        {.status = 200, .body = "{}", .send_rc = 1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .body = "{}", .send_rc = 1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .body = "{}", .send_rc = 1, .send_error = "lookup synthetic: no such host", .error = "lookup synthetic: no such host"},
        {.status = 200, .body = "{}", .send_rc = 1, .error = "HTTP transport failed"},
        {.status = 200, .body = "{}", .send_rc = 1, .send_error = "unsupported: synthetic PUBLIC transport",
         .error = "unsupported: synthetic PUBLIC transport"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {.token = token, .url = "https://jira-check.invalid/rest/api/2/myself"};
        expected_requests requests = {.items = &request, .count = 1};
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {(unsigned char *)cases[i].body, strlen(cases[i].body)},
                         .body_error = cases[i].read_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &requests,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "jira-pat-test"};
        expected_result expected = {.token = token, .url = list[0], .verified = cases[i].verified,
                                   .error = cases[i].error, .name = cases[i].name, .email = cases[i].email};
        expect_results(detector, &ctx, true, input, strlen(input), &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1 && requests.seen == 1);
        expected = (expected_result){.token = token, .url = list[0]};
        expect_results(detector, &ctx, false, input, strlen(input), &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1); /* No invalid-host cache. */
    }
}

static void test_request_urls(const br_detector *detector)
{
    const struct { const char *base, *request; } supported[] = {
        {"http://user:pass@jira-shapes.invalid:8080/old?discard=1#frag",
         "http://user:pass@jira-shapes.invalid:8080/rest/api/2/myself#frag"},
        {"https://jira-shapes.invalid/old?#frag", "https://jira-shapes.invalid/rest/api/2/myself?#frag"},
    };
    char input[64];
    snprintf(input, sizeof(input), "atlassian %s", token);
    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); ++i) {
        const char *list[] = {supported[i].base};
        br_endpoints endpoints = {.configured = list, .nconfigured = 1};
        expected_request request = {.token = token, .url = supported[i].request};
        expected_requests requests = {.items = &request, .count = 1};
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
        expected_result expected = {.token = token, .url = list[0], .verified = true};
        expect_results(detector, &ctx, true, input, strlen(input), &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1 && requests.seen == 1);
    }
    const char *unsupported[] = {
        "", "relative/path", "https:opaque", "HTTPS://jira.invalid",
        "https://jira.invalid/old%2Fpath", "https://jira.invalid:080/path", "http://127.1/path",
    };
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
        const char *list[] = {unsupported[i]};
        br_endpoints endpoints = {.configured = list, .nconfigured = 1};
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
        expected_result expected = {.token = token, .url = list[0],
            .error = "unsupported: Data Center URL form or normalization"};
        expect_results(detector, &ctx, true, input, strlen(input), &expected, 1);
        CHECK(!http.calls && !http.releases);
    }
}

static void test_per_token_short_circuit(const br_detector *detector)
{
    const char *list[] = {"https://denied.invalid/base", "https://good.invalid/old?discard=1", "https://skipped.invalid"};
    br_endpoints endpoints = {.configured = list, .nconfigured = 3};
    const expected_request expected_requests_list[] = {
        {token, "https://denied.invalid/rest/api/2/myself", 401},
        {token, "https://good.invalid/rest/api/2/myself", 200},
        {other_token, "https://denied.invalid/rest/api/2/myself", 401},
        {other_token, "https://good.invalid/rest/api/2/myself", 200},
    };
    expected_requests requests = {.items = expected_requests_list, .count = 4};
    test_http http = {.response = {.body_error = "ignored JSON read failure"},
                      .inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
    char input[192];
    snprintf(input, sizeof(input), "jira %s\njira %s\njira %s", token, other_token, token);
    const expected_result results[] = {
        {.token = token, .url = list[0]}, {.token = token, .url = list[1], .verified = true},
        {.token = other_token, .url = list[0]}, {.token = other_token, .url = list[1], .verified = true},
    };
    expect_results(detector, &ctx, true, input, strlen(input), results, 4);
    CHECK(http.calls == 4 && http.releases == 4 && requests.seen == 15);
}

int main(void)
{
    unsigned char raw[33];
    memcpy(raw, "123456789012:abcdefghijklmnopqrst", sizeof(raw));
    raw[13] = 0;
    raw[32] = 0xff; /* Ending '/' must not require a trailing word boundary. */
    CHECK(EVP_EncodeBlock((unsigned char *)token, raw, sizeof(raw)) == 44);
    raw[0] = '9';
    raw[32] = 0xfe;
    CHECK(EVP_EncodeBlock((unsigned char *)other_token, raw, sizeof(raw)) == 44);
    CHECK(token[43] == '/' && other_token[43] == '+');
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_endpoints(detector);
    test_verification(detector);
    test_request_urls(detector);
    test_per_token_short_circuit(detector);
    return test_finish("JiraDataCenterPAT");
}
