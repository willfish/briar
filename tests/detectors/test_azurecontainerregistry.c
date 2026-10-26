/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <time.h>

static const char password0[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF+ACR123456";
static const char password1[] = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210abcdef+ACR654321";
static const char password2[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef+ACR987654";
static int64_t now_ns = 1700000000000000000LL;
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;

int timespec_get(struct timespec *out, int base)
{
    if (base != TIME_UTC) return 0;
    out->tv_sec = (time_t)(now_ns / 1000000000);
    out->tv_nsec = (long)(now_ns % 1000000000);
    return TIME_UTC;
}

typedef struct {
    const char *username, *password;
    bool verified;
    const char *error;
} expected_result;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azurecontainerregistry_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 958 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureContainerRegistry") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure's container registry is used to store docker containers. An API key "
        "can be used to override existing containers, read sensitive data, and do "
        "other operations inside the container registry."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".azurecr.io"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint && detector->false_positive);
    br_result generic_wordlist_case = {.raw = {(unsigned char *)"example", 7}};
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, &generic_wordlist_case, &reason));
    CHECK(reason && !reason[0]);
    free(reason);
    CHECK(!detector->false_positive(detector, NULL, NULL));
    const void *patterns = detector->state;
    CHECK(br_azurecontainerregistry_init(&again, &error) == 0 && !error && again == detector && again->state == patterns);
    CHECK(br_azurecontainerregistry_init(&again, NULL) == 0 && again == detector);
    CHECK(br_azurecontainerregistry_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_azurecontainerregistry_init(NULL, NULL) != 0);
    return detector;
}

static void check_text(br_json *object, const char *field, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, field, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK(!strcmp(json_object_get_string(value), expected));
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 958 && !result->detector_name);
    CHECK(result->raw.len == 52 && !memcmp(result->raw.data, expected->password, 52));
    char raw_v2[208];
    int n = snprintf(raw_v2, sizeof(raw_v2), "{\"username\":\"%s\",\"password\":\"%s\"}", expected->username, expected->password);
    CHECK(n > 0 && (size_t)n < sizeof(raw_v2));
    CHECK(result->raw_v2.len == (size_t)n && !memcmp(result->raw_v2.data, raw_v2, (size_t)n));
    CHECK(result->redacted && !strcmp(result->redacted, expected->username));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "username", expected->username);
    check_text(result->secret_parts, "password", expected->password);
    CHECK(result->verified == expected->verified);
    if (expected->error) {
        CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
        CHECK(!strstr(result->verification_error, expected->password));
    } else CHECK(!result->verification_error);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const void *input, size_t len, const expected_result *expected, size_t count)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&results.items[i], &expected[i]);
    br_results_clear(&results);
}

static void scan_pair(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *username, const char *password, const expected_result *expected, size_t count)
{
    char input[384];
    int n = snprintf(input, sizeof(input), "%s.azurecr.io\n%s", username, password);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_results(detector, ctx, verify, input, (size_t)n, expected, count);
}

static void test_extraction(const br_detector *detector)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expected_result one = {.username = "regone", .password = password0};
    scan_pair(detector, &ctx, false, one.username, password0, &one, 1);
    expect_results(detector, &ctx, false, NULL, 0, NULL, 0);
    expect_results(detector, &ctx, true, password0, 52, NULL, 0);
    expect_results(detector, &ctx, true, "regone.azurecr.io", strlen("regone.azurecr.io"), NULL, 0);
    scan_pair(detector, &ctx, true, "privatelink", password0, NULL, 0);
    scan_pair(detector, &ctx, true, "myacr", password0, NULL, 0);
    one.username = "myacrx";
    scan_pair(detector, &ctx, false, one.username, password0, &one, 1);
    one.username = "example";
    scan_pair(detector, &ctx, false, one.username, password0, &one, 1);
    one.username = "abc";
    scan_pair(detector, &ctx, false, "UPPERabc", password0, &one, 1); /* No leading boundary or lowercasing. */
    scan_pair(detector, &ctx, false, "-abc", password0, &one, 1);
    scan_pair(detector, &ctx, false, "ab", password0, NULL, 0);
    scan_pair(detector, &ctx, false, "abc-", password0, NULL, 0);
    char input[2048], username[104], changed[54];
    snprintf(input, sizeof(input), "regone.AZURECR.IO\n%s", password0);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0);
    one.username = "regone";
    snprintf(input, sizeof(input), "regone.azurecr.io.evil\n%s", password0);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1);
    memset(username, 'a', 102);
    username[102] = '\0';
    one.username = username;
    scan_pair(detector, &ctx, false, username, password0, &one, 1);
    snprintf(input, sizeof(input), "b%s.azurecr.io\n%s", username, password0);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1); /* Last 102, not strict DNS validation. */
    one.username = "regone";
    memcpy(changed, password0, sizeof(password0));
    changed[43] = 'a';
    scan_pair(detector, &ctx, false, one.username, changed, NULL, 0);
    memcpy(changed, password0, sizeof(password0));
    changed[10] = '=';
    scan_pair(detector, &ctx, false, one.username, changed, NULL, 0);
    snprintf(input, sizeof(input), "regone.azurecr.io\n%.51s", password0);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0);
    const char *edges[] = {"_%s", "%s_", "%sQ"};
    for (size_t i = 0; i < 3; ++i) {
        char wrapped[56];
        snprintf(wrapped, sizeof(wrapped), edges[i], password0);
        scan_pair(detector, &ctx, false, one.username, wrapped, NULL, 0);
    }
    snprintf(input, sizeof(input), "regone.azurecr.io\n%s=", password0);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1); /* No extra Base64 validation. */
    memcpy(changed, password0, sizeof(password0));
    changed[0] = '+';
    scan_pair(detector, &ctx, false, one.username, changed, NULL, 0); /* Nonword-to-nonword is not a boundary. */
    snprintf(input, sizeof(input), "regone.azurecr.io\nx%s", changed);
    one.password = changed;
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1);
    const char below[] = "abcdefghiabcdefghiabcdefghiabcdefghiabcdef+ACR123456";
    const char above[] = "abcdefghijabcdefghijabcdefghijabcdefghijab+ACR123456";
    CHECK(strlen(below) == 52 && strlen(above) == 52);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)below, 52}) < 4.0);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)above, 42}) < 4.0);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)above, 52}) >= 4.0);
    scan_pair(detector, &ctx, true, one.username, below, NULL, 0);
    one.password = above;
    scan_pair(detector, &ctx, false, one.username, above, &one, 1); /* Entropy covers all 52 bytes. */
    one.password = password0;
    size_t at = (size_t)snprintf(input, sizeof(input), "regone.azurecr.io");
    memset(input + at, '\n', 1100);
    memcpy(input + at + 1100, password0, 52);
    expect_results(detector, &ctx, false, input, at + 1100 + 52, &one, 1);
    CHECK(!http.calls && !http.releases);
}

typedef struct {
    const char *username, *password;
    int status;
    const char *send_error;
} expected_request;
typedef struct { const expected_request *items; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const expected_request *entry = &expected->items[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    char url[160], plain[156], basic[216];
    snprintf(url, sizeof(url), "https://%s.azurecr.io/v2/", entry->username);
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 958);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    int n = snprintf(plain, sizeof(plain), "%s:%s", entry->username, entry->password);
    CHECK(n > 0 && (size_t)n < sizeof(plain));
    memcpy(basic, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)basic + 6, (const unsigned char *)plain, n) > 0);
    if (!strcmp(entry->username, "regone") && !strcmp(entry->password, password0))
        CHECK(!strcmp(basic, "Basic cmVnb25lOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OUFCQ0RFRitBQ1IxMjM0NTY="));
    size_t authorization = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++authorization;
            CHECK(!strcmp(header->value, basic));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog azurecr-test" : "TruffleHog"));
        } else CHECK(!"unexpected Azure Container Registry request header");
    }
    CHECK(authorization == 1 && agent == 1);
    if (entry->status || entry->send_error) {
        if (entry->status) http->response.status = entry->status;
        http->send_error = entry->send_error;
        http->send_rc = entry->send_error ? 1 : 0;
    }
}

static void test_global_consumption_and_break(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "regone.azurecr.io\nregtwo.azurecr.io\nregone.azurecr.io\n%s\n%s\n%s\n%s",
             password0, password1, password2, password0);
    const char *users[] = {"regone", "regtwo"};
    const char *passwords[] = {password0, password1, password2};
    expected_result all[6];
    for (size_t u = 0; u < 2; ++u)
        for (size_t k = 0; k < 3; ++k) all[u * 3 + k] = (expected_result){.username = users[u], .password = passwords[k]};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, false, input, strlen(input), all, 6);
    CHECK(!http.calls && !http.releases);
    const expected_request request_list[] = {
        {"regone", password0, 401, NULL}, {"regone", password1, 200, NULL},
        {"regtwo", password0, 401, NULL}, {"regtwo", password2, 200, NULL},
    };
    expected_requests requests = {request_list, 4};
    http = (test_http){.response = {.body_error = "ignored body: no such host"},
                       .inspect = inspect_request, .user = &requests};
    const expected_result stopped[] = {
        {.username = "regone", .password = password0},
        {.username = "regone", .password = password1, .verified = true},
        {.username = "regtwo", .password = password0},
        {.username = "regtwo", .password = password2, .verified = true},
    };
    expect_results(detector, &ctx, true, input, strlen(input), stopped, 4);
    CHECK(http.calls == 4 && http.releases == 4);
    /* Consumption is scan-local, and verification-disabled products never consume. */
    expect_results(detector, &ctx, false, input, strlen(input), all, 6);
    CHECK(http.calls == 4 && http.releases == 4);
    snprintf(input, sizeof(input), "regone.azurecr.io\nregtwo.azurecr.io\n%s", password0);
    const expected_request only_request = {"regone", password0, 200, NULL};
    requests = (expected_requests){&only_request, 1};
    http = (test_http){.inspect = inspect_request, .user = &requests};
    const expected_result only = {.username = "regone", .password = password0, .verified = true};
    expect_results(detector, &ctx, true, input, strlen(input), &only, 1);
    CHECK(http.calls == 1 && http.releases == 1); /* No candidate remains for regtwo. */
}

static void test_status_and_errors(const br_detector *detector)
{
    char sensitive[144], redacted[144];
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified, cached;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, false, NULL}, {401, 0, NULL, false, false, NULL},
        {403, 0, NULL, false, false, "unexpected HTTP response status 403"},
        {201, 0, NULL, false, false, "unexpected HTTP response status 201"},
        {500, 0, NULL, false, false, "unexpected HTTP response status 500"},
        {200, 1, "lookup synthetic: no such host", false, true, NULL},
        {200, 1, "lookup synthetic: No such host", false, false, "lookup synthetic: No such host"},
        {200, 1, sensitive, false, false, redacted},
        {200, 1, "context canceled", false, false, "context canceled"},
        {200, 1, "context deadline exceeded", false, false, "context deadline exceeded"},
        {200, 1, NULL, false, false, "HTTP transport failed"},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    const br_header challenge[] = {{"WWW-Authenticate", "Bearer realm=\"https://must-not-request.invalid/token\""}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char username[24];
        snprintf(username, sizeof(username), "status%02zu", i);
        snprintf(sensitive, sizeof(sensitive), "user=%s password=%s rejected", username, password0);
        snprintf(redacted, sizeof(redacted), "user=%s password=[REDACTED] rejected", username);
        expected_request entry = {username, password0, 0, NULL};
        expected_requests requests = {&entry, 1};
        test_http http = {
            .response = {.status = cases[i].status, .headers = challenge, .nheaders = 1,
                         .body = {body, sizeof(body)}, .body_error = "ignored drain: no such host"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &requests,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "azurecr-test"};
        expected_result expected = {.username = username, .password = password0,
                                   .verified = cases[i].verified, .error = cases[i].error};
        scan_pair(detector, &ctx, true, username, password0, &expected, cases[i].cached ? 0 : 1);
        CHECK(http.calls == 1 && http.releases == 1);
        expected = (expected_result){.username = username, .password = password0};
        scan_pair(detector, &ctx, false, username, password0, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1); /* NoV ignores even a freshly cached hostname. */
        http.calls = http.releases = 0;
        http.send_error = NULL;
        http.send_rc = 0;
        http.response.status = 200;
        expected.verified = true;
        scan_pair(detector, &ctx, true, username, password0, &expected, cases[i].cached ? 0 : 1);
        CHECK(http.calls == (cases[i].cached ? 0u : 1u) && http.releases == http.calls);
    }
}

static void test_dns_cache(const br_detector *detector)
{
    char input[384], cached_input[192];
    snprintf(input, sizeof(input), "cachedreg.azurecr.io\nhealthyreg.azurecr.io\n%s\n%s", password0, password1);
    snprintf(cached_input, sizeof(cached_input), "cachedreg.azurecr.io\n%s\n%s", password0, password1);
    const expected_request request_list[] = {
        {"cachedreg", password0, 0, "lookup synthetic: no such host"},
        {"healthyreg", password0, 401, NULL}, {"healthyreg", password1, 401, NULL},
    };
    expected_requests requests = {request_list, 3};
    test_http http = {.inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const expected_result survivors[] = {
        {.username = "healthyreg", .password = password0}, {.username = "healthyreg", .password = password1},
    };
    const int64_t born = now_ns;
    expect_results(detector, &ctx, true, input, strlen(input), survivors, 2);
    CHECK(http.calls == 3 && http.releases == 3);
    const expected_result no_verify[] = {
        {.username = "cachedreg", .password = password0}, {.username = "cachedreg", .password = password1},
        {.username = "healthyreg", .password = password0}, {.username = "healthyreg", .password = password1},
    };
    expect_results(detector, &ctx, false, input, strlen(input), no_verify, 4);
    CHECK(http.calls == 3 && http.releases == 3);
    const br_detector *again = NULL;
    CHECK(br_azurecontainerregistry_init(&again, NULL) == 0 && again == detector);
    requests = (expected_requests){0};
    http = (test_http){.inspect = inspect_request, .user = &requests};
    expect_results(again, &ctx, true, cached_input, strlen(cached_input), NULL, 0);
    CHECK(!http.calls && !http.releases);
    now_ns = born + ttl_ns;
    expect_results(detector, &ctx, true, cached_input, strlen(cached_input), NULL, 0);
    CHECK(!http.calls && !http.releases);
    ++now_ns;
    const expected_request expired_request = {"cachedreg", password0, 200, NULL};
    requests = (expected_requests){&expired_request, 1};
    http = (test_http){.inspect = inspect_request, .user = &requests};
    const expected_result expired_result = {.username = "cachedreg", .password = password0, .verified = true};
    expect_results(detector, &ctx, true, cached_input, strlen(cached_input), &expired_result, 1);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_dns_preserves_earlier_results(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "partialreg.azurecr.io\n%s\n%s\n%s", password0, password1, password2);
    const expected_request request_list[] = {
        {"partialreg", password0, 401, NULL}, {"partialreg", password1, 0, "lookup: no such host"},
    };
    expected_requests requests = {request_list, 2};
    test_http http = {.inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const expected_result earlier = {.username = "partialreg", .password = password0};
    expect_results(detector, &ctx, true, input, strlen(input), &earlier, 1);
    CHECK(http.calls == 2 && http.releases == 2);
    const expected_result no_verify[] = {
        {.username = "partialreg", .password = password0},
        {.username = "partialreg", .password = password1},
        {.username = "partialreg", .password = password2},
    };
    expect_results(detector, &ctx, false, input, strlen(input), no_verify, 3);
    CHECK(http.calls == 2 && http.releases == 2);
}

int main(void)
{
    CHECK(strlen(password0) == 52 && strlen(password1) == 52 && strlen(password2) == 52);
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_global_consumption_and_break(detector);
    test_status_and_errors(detector);
    test_dns_cache(detector);
    test_dns_preserves_earlier_results(detector);
    return test_finish("AzureContainerRegistry");
}
