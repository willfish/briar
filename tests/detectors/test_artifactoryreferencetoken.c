/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/endpoints.h"
#include "../support/detector_test.h"
#include <time.h>

typedef struct { const char *token, *domain; } expected_pair;
static char token[65], other_token[65];
static int64_t now_ns = 1700000000000000000LL;
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;

/* The shared cache uses this clock; no sleeping, DNS, or network is involved. */
int timespec_get(struct timespec *time, int base)
{
    if (base != TIME_UTC) return 0;
    time->tv_sec = (time_t)(now_ns / 1000000000);
    time->tv_nsec = (long)(now_ns % 1000000000);
    return TIME_UTC;
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_artifactoryreferencetoken_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 1042 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ArtifactoryReferenceToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "JFrog Artifactory is a binary repository manager. Reference tokens are "
        "64-character access tokens that can be used to authenticate API requests, "
        "providing access to repositories, builds, and artifacts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cmVmdGtu"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive);
    CHECK(detector->validate_endpoints == br_endpoints_validate_configured);
    CHECK(detector->cloud_endpoint && !detector->cloud_endpoint[0]);
    const void *patterns = detector->state;
    CHECK(br_artifactoryreferencetoken_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == patterns);
    CHECK(br_artifactoryreferencetoken_init(&again, NULL) == 0 && again == detector);
    CHECK(br_artifactoryreferencetoken_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_artifactoryreferencetoken_init(NULL, NULL) != 0);
    return detector;
}

static bool matches_pair(const br_result *result, expected_pair pair)
{
    size_t domain_len = strlen(pair.domain);
    return result->raw.len == 64 && !memcmp(result->raw.data, pair.token, 64) &&
           result->raw_v2.len == 64 + domain_len &&
           !memcmp(result->raw_v2.data, pair.token, 64) &&
           !memcmp(result->raw_v2.data + 64, pair.domain, domain_len);
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 1042 && !result->detector_name);
    CHECK(matches_pair(result, pair));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.token));
    CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.domain));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const void *input, size_t len, const expected_pair *pairs,
                           size_t count, bool verified, const char *error)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(count <= 8 && results.len == count);
    unsigned seen = 0;
    for (size_t r = 0; r < results.len; ++r) {
        size_t p = 0;
        for (; p < count; ++p) if (matches_pair(&results.items[r], pairs[p])) break;
        CHECK(p < count && !(seen & (1u << p)));
        seen |= 1u << p;
        check_pair(&results.items[r], pairs[p]);
        CHECK(results.items[r].verified == verified);
        if (error) {
            CHECK(results.items[r].verification_error);
            CHECK(!strcmp(results.items[r].verification_error, error));
        } else {
            CHECK(!results.items[r].verification_error);
        }
    }
    CHECK(seen == (1u << count) - 1);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed[65], host[80];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expected_pair one = {token, "extract-xy.jfrog.io"};
    const struct { const char *format; size_t count; } cases[] = {
        {"%s extract-xy.jfrog.io", 1},
        {"'%s' https://extract-xy.jfrog.io/path", 1},
        {"%s %s extract-xy.jfrog.io extract-xy.jfrog.io", 1},
        {"%s", 0},
        {"extract-xy.jfrog.io", 0},
        {"_%s extract-xy.jfrog.io", 0},
        {"%s_ extract-xy.jfrog.io", 0},
        {"%sQ extract-xy.jfrog.io", 0},
        {"%.63s extract-xy.jfrog.io", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, token, token);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_results(detector, &ctx, false, input, (size_t)len, &one, cases[i].count, false, NULL);
    }
    expect_results(detector, &ctx, false, NULL, 0, NULL, 0, false, NULL);
    memcpy(changed, token, sizeof(changed));
    memcpy(changed, "CMVMDGTU", 8);
    snprintf(input, sizeof(input), "%s extract-xy.jfrog.io", changed);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    for (size_t i = 0; i < 2; ++i) {
        memcpy(changed, token, sizeof(changed));
        changed[20] = i ? '=' : '+';
        snprintf(input, sizeof(input), "%s extract-xy.jfrog.io", changed);
        expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    }
    memcpy(changed, "cmVmdGtu", 8);
    memset(changed + 8, 'a', 56);
    changed[64] = '\0';
    snprintf(input, sizeof(input), "%s extract-xy.jfrog.io", changed);
    expected_pair low_entropy = {changed, one.domain};
    expect_results(detector, &ctx, false, input, strlen(input), &low_entropy, 1, false, NULL);

    const struct { const char *input, *domain; } hosts[] = {
        {"ab.jfrog.io", "ab.jfrog.io"},
        {"a.jfrog.io", NULL},
        {"ab.jfrog.ioevil", "ab.jfrog.io"},
        {"AZ.jfrog.io", "AZ.jfrog.io"},
        {"ab.JFROG.io", NULL},
        {"_ab.jfrog.io", NULL},
        {"a-b.jfrog.io", "a-b.jfrog.io"},
        {"ab-.jfrog.io", NULL},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s", token, hosts[i].input);
        expected_pair pair = {token, hosts[i].domain};
        expect_results(detector, &ctx, false, input, strlen(input), &pair,
                       hosts[i].domain ? 1 : 0, false, NULL);
    }
    for (size_t label_len = 63; label_len <= 64; ++label_len) {
        memset(host, 'a', label_len);
        memcpy(host + label_len, ".jfrog.io", sizeof(".jfrog.io"));
        snprintf(input, sizeof(input), "%s %s", token, host);
        expected_pair pair = {token, host};
        expect_results(detector, &ctx, false, input, strlen(input), &pair,
                       label_len == 63 ? 1 : 0, false, NULL);
    }
    input[0] = '\0';
    memcpy(input + 1, token, 64);
    input[65] = '\0';
    memcpy(input + 66, one.domain, strlen(one.domain));
    expect_results(detector, &ctx, false, input, 66 + strlen(one.domain), &one, 1, false, NULL);
    memcpy(input, token, 64);
    memset(input + 64, '\n', 1100);
    memcpy(input + 1164, one.domain, strlen(one.domain));
    expect_results(detector, &ctx, false, input, 1164 + strlen(one.domain), &one, 1, false, NULL);
    CHECK(!http.calls && !http.releases);
}

static void test_endpoints(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "%s endpoint-xy.jfrog.io", token);
    expected_pair found = {token, "endpoint-xy.jfrog.io"};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, NULL, false, input, strlen(input), &found, 1, false, NULL);
    expect_results(detector, &ctx, false, input, strlen(input), &found, 1, false, NULL);
    br_endpoints endpoints = {0};
    ctx.endpoints = &endpoints;
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    endpoints.use_found = true;
    expect_results(detector, &ctx, false, input, strlen(input), &found, 1, false, NULL);
    endpoints = (br_endpoints){.use_cloud = true};
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    endpoints.cloud = "https://cloud.invalid";
    expected_pair cloud = {token, "cloud.invalid"};
    expect_results(detector, &ctx, false, input, strlen(input), &cloud, 1, false, NULL);
    endpoints.use_cloud = false;
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);

    const char *configured[] = {
        "https://endpoint-xy.jfrog.io", "endpoint-xy.jfrog.io",
        "https://custom.invalid/path/", "https://https://double.invalid",
        "HTTPS://UPPER.invalid", "http://plain.invalid", "", "https://",
    };
    endpoints = (br_endpoints){.configured = configured, .nconfigured = 8,
                              .cloud = "https://endpoint-xy.jfrog.io",
                              .use_cloud = true, .use_found = true};
    const expected_pair normalized[] = {
        {token, "endpoint-xy.jfrog.io"}, {token, "custom.invalid/path/"},
        {token, "https://double.invalid"}, {token, "HTTPS://UPPER.invalid"},
        {token, "http://plain.invalid"}, {token, ""},
    };
    expect_results(detector, &ctx, false, input, strlen(input), normalized, 6, false, NULL);
    const char *empty[] = {""};
    endpoints = (br_endpoints){.configured = empty, .nconfigured = 1};
    expected_pair empty_domain = {token, ""};
    expect_results(detector, &ctx, false, input, strlen(input), &empty_domain, 1, false, NULL);
    expect_results(detector, &ctx, true, found.domain, strlen(found.domain), NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
}

typedef struct {
    const expected_pair *pairs;
    size_t count;
    unsigned seen;
    int64_t advance_on_first;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(expected->count <= 8 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 1042);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    const char *authorization = NULL;
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++auth;
            authorization = header->value;
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ?
                          "TruffleHog reference-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected reference-token request header");
        }
    }
    CHECK(auth == 1 && agent == 1 && authorization);
    size_t p = 0;
    for (; p < expected->count; ++p) {
        char url[256], bearer[72];
        snprintf(url, sizeof(url), "https://%s/access/api/v1/tokens/me", expected->pairs[p].domain);
        snprintf(bearer, sizeof(bearer), "Bearer %s", expected->pairs[p].token);
        if (!strcmp(request->url, url) && !strcmp(authorization, bearer)) break;
    }
    CHECK(p < expected->count && !(expected->seen & (1u << p)));
    expected->seen |= 1u << p;
    if (http->calls == 1) now_ns += expected->advance_on_first;
}

static void test_unique_product(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s %s %s first-xy.jfrog.io first-xy.jfrog.io second-xy.jfrog.io",
             token, other_token, token);
    const char *configured[] = {"https://first-xy.jfrog.io", "first-xy.jfrog.io", "custom.invalid"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 3,
                             .cloud = "https://second-xy.jfrog.io", .use_cloud = true, .use_found = true};
    const expected_pair pairs[] = {
        {token, "first-xy.jfrog.io"}, {token, "second-xy.jfrog.io"}, {token, "custom.invalid"},
        {other_token, "first-xy.jfrog.io"}, {other_token, "second-xy.jfrog.io"}, {other_token, "custom.invalid"},
    };
    expected_requests expected = {.pairs = pairs, .count = 6};
    test_http http = {
        .response = {.status = 403, .body_error = "ignored drain: no such host"},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "reference-test"};
    expect_results(detector, &ctx, true, input, strlen(input), pairs, 6, true, NULL);
    CHECK(http.calls == 6 && http.releases == 6 && expected.seen == 63);
}

static void test_verification(const br_detector *detector)
{
    const br_header json[] = {{"Content-Type", "application/json"}};
    const br_header mixed_name[] = {{"cOnTeNt-TyPe", "application/json; charset=utf-8"}};
    const br_header substring[] = {{"Content-Type", "prefixapplication/jsonsuffix"}};
    const br_header html[] = {{"Content-Type", "text/html"}};
    const br_header wrong_case[] = {{"Content-Type", "Application/JSON"}};
    const br_header wrong_name[] = {{"X-Content-Type", "application/json"}};
    const br_header html_first[] = {{"Content-Type", "text/html"}, {"content-type", "application/json"}};
    const br_header empty_first[] = {{"CONTENT-TYPE", ""}, {"Content-Type", "application/json"}};
    const br_header json_first[] = {{"content-type", "application/json"}, {"Content-Type", "text/html"}};
    const unsigned char body[] = {0, 0xff, '<', 'h', 't', 'm', 'l', '>'};
    char sensitive[320], redacted[160];
    const struct {
        int status;
        const br_header *headers;
        size_t nheaders;
        int send_rc;
        const char *send_error;
        bool verified, suppressed;
        const char *error;
    } cases[] = {
        {.status = 200, .headers = json, .nheaders = 1, .verified = true},
        {.status = 200, .headers = mixed_name, .nheaders = 1, .verified = true},
        {.status = 200, .headers = substring, .nheaders = 1, .verified = true},
        {.status = 200, .suppressed = true},
        {.status = 200, .headers = html, .nheaders = 1, .suppressed = true},
        {.status = 200, .headers = wrong_case, .nheaders = 1, .suppressed = true},
        {.status = 200, .headers = wrong_name, .nheaders = 1, .suppressed = true},
        {.status = 200, .headers = html_first, .nheaders = 2, .suppressed = true},
        {.status = 200, .headers = empty_first, .nheaders = 2, .suppressed = true},
        {.status = 200, .headers = json_first, .nheaders = 2, .verified = true},
        {.status = 403, .verified = true},
        {.status = 401},
        {.status = 302, .error = "unexpected HTTP response status 302"},
        {.status = 404, .error = "unexpected HTTP response status 404"},
        {.status = 500, .error = "unexpected HTTP response status 500"},
        {.status = 200, .send_rc = 1, .error = "HTTP transport failed"},
        {.status = 200, .send_rc = 1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = 1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1, .send_error = sensitive, .error = redacted},
        {.status = 200, .send_rc = 1, .send_error = "lookup synthetic: no such host", .suppressed = true},
        {.status = 200, .send_rc = 1, .send_error = "lookup synthetic: NO SUCH HOST", .error = "lookup synthetic: NO SUCH HOST"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char host[64], configured[80];
        snprintf(host, sizeof(host), "verify%02zu.invalid", i);
        snprintf(configured, sizeof(configured), "https://%s", host);
        snprintf(sensitive, sizeof(sensitive), "host=%s token=%s again=%s", host, token, token);
        snprintf(redacted, sizeof(redacted), "host=%s token=[REDACTED] again=[REDACTED]", host);
        const char *list[] = {configured};
        br_endpoints endpoints = {.configured = list, .nconfigured = 1};
        expected_pair pair = {token, host};
        expected_requests expected = {.pairs = &pair, .count = 1};
        test_http http = {
            .response = {.status = cases[i].status, .headers = cases[i].headers,
                         .nheaders = cases[i].nheaders, .body = {body, sizeof(body)},
                         .body_error = "ignored read/drain: no such host"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
        expect_results(detector, &ctx, true, token, 64, &pair, cases[i].suppressed ? 0 : 1,
                       cases[i].verified, cases[i].error);
        CHECK(http.calls == 1 && http.releases == 1 && expected.seen == 1);
        /* Suppression is host-scoped, including another token with verification off. */
        pair.token = other_token;
        expect_results(detector, &ctx, false, other_token, 64, &pair,
                       cases[i].suppressed ? 0 : 1, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }

    const char *empty[] = {""};
    br_endpoints endpoints = {.configured = empty, .nconfigured = 1};
    expected_pair pair = {token, ""};
    expected_requests expected = {.pairs = &pair, .count = 1};
    test_http http = {.send_rc = 1, .send_error = "http: no Host in request URL",
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
    expect_results(detector, &ctx, true, token, 64, &pair, 1, false, "http: no Host in request URL");
    expect_results(detector, &ctx, false, token, 64, &pair, 1, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && expected.seen == 1);
}

static void test_cache_lifetime(const br_detector *detector)
{
    const char *list[] = {"ttl-first.invalid"};
    br_endpoints endpoints = {.configured = list, .nconfigured = 1};
    expected_pair pair = {token, list[0]};
    expected_requests expected = {.pairs = &pair, .count = 1};
    test_http http = {.send_rc = 1, .send_error = "lookup synthetic: no such host",
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
    const int64_t start = now_ns;
    expect_results(detector, &ctx, true, token, 64, NULL, 0, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    const br_detector *again = NULL;
    CHECK(br_artifactoryreferencetoken_init(&again, NULL) == 0 && again == detector);
    expect_results(again, &ctx, false, other_token, 64, NULL, 0, false, NULL);
    list[0] = "TTL-FIRST.invalid";
    pair.domain = list[0];
    expect_results(detector, &ctx, false, token, 64, &pair, 1, false, NULL);

    /* A second host gets its own expiration, from the 200/non-JSON branch. */
    now_ns += 17;
    list[0] = "ttl-second.invalid";
    pair.domain = list[0];
    expected.seen = 0;
    http.calls = http.releases = 0;
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 200};
    expect_results(detector, &ctx, true, token, 64, NULL, 0, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && expected.seen == 1);
    now_ns = start + ttl_ns;
    list[0] = "ttl-first.invalid";
    pair.domain = list[0];
    expect_results(detector, &ctx, true, token, 64, NULL, 0, false, NULL);
    ++now_ns;
    expect_results(detector, &ctx, false, token, 64, &pair, 1, false, NULL);
    list[0] = "ttl-second.invalid";
    pair.domain = list[0];
    expect_results(detector, &ctx, false, token, 64, NULL, 0, false, NULL);
    now_ns = start + ttl_ns + 17;
    expect_results(detector, &ctx, false, token, 64, NULL, 0, false, NULL);
    ++now_ns;
    expect_results(detector, &ctx, false, token, 64, &pair, 1, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_cached_host_stays_local(const br_detector *detector)
{
    const char *list[] = {"retained.invalid", "progress.invalid"};
    br_endpoints endpoints = {.configured = list, .nconfigured = 1};
    expected_pair prime = {token, list[0]};
    expected_requests expected_prime = {.pairs = &prime, .count = 1};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected_prime};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints};
    expect_results(detector, &ctx, true, token, 64, NULL, 0, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    endpoints.nconfigured = 2;
    char input[132];
    snprintf(input, sizeof(input), "%s %s", token, other_token);
    const expected_pair pairs[] = {
        {token, list[1]}, {other_token, list[0]}, {other_token, list[1]},
    };
    /* The first token skips the cached host. Its other request advances the
     * clock, so the second token must still be able to visit the expired host. */
    expected_requests expected = {.pairs = pairs, .count = 3, .advance_on_first = ttl_ns + 1};
    http = (test_http){.response = {.status = 401}, .inspect = inspect_request, .user = &expected};
    expect_results(detector, &ctx, true, input, strlen(input), pairs, 3, false, NULL);
    CHECK(http.calls == 3 && http.releases == 3 && expected.seen == 7);
}

int main(void)
{
    memcpy(token, "cmVmdGtu", 8);
    test_secret(token + 8, 56, 0);
    token[24] = 'Z';
    memcpy(other_token, "cmVmdGtu", 8);
    test_secret(other_token + 8, 56, 9);
    other_token[24] = 'A';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_endpoints(detector);
    test_unique_product(detector);
    test_verification(detector);
    test_cache_lifetime(detector);
    test_cached_host_stays_local(detector);
    return test_finish("ArtifactoryReferenceToken");
}
