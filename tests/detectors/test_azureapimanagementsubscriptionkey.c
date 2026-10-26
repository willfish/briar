/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], second_key[33];
static const char base_url[] = "https://example.azure-api.net";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_503_strdup;

/* One-shot reproduction of the observed setter-allocation/cache collision. */
char *strdup(const char *text)
{
    if (fail_status_503_strdup && !strcmp(text, status_503)) {
        fail_status_503_strdup = false;
        return NULL;
    }
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azureapimanagementsubscriptionkey_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Azure API Management subscription detector output"));
    free(error); error = NULL;
    CHECK(!br_azureapimanagementsubscriptionkey_init(&detector, &error) && detector && !error);
    CHECK(!br_azureapimanagementsubscriptionkey_init(&again, NULL) && again == detector);
    CHECK(detector->type == 1019 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureAPIManagementSubscriptionKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".azure-api.net"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && detector->false_positive);
    CHECK(!detector->clean && !detector->clean_always && !detector->validate_endpoints && !detector->cloud_endpoint);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, NULL, &reason));
    CHECK(reason && !strcmp(reason, ""));
    free(reason);
    CHECK(!detector->false_positive(detector, NULL, NULL));
    return detector;
}

static void check_part(br_json *parts, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected));
    CHECK(!strcmp(json_object_get_string(value), expected));
}

static void check_result(const br_detector *detector, const br_result *result, const char *url,
                          const char *secret, bool verified, const char *error)
{
    size_t url_len = strlen(url);
    CHECK(result->detector_type == 1019 && !result->detector_name);
    CHECK(result->raw.len == url_len && !memcmp(result->raw.data, url, url_len));
    CHECK(result->raw_v2.data && result->raw_v2.len == url_len + 33);
    CHECK(!memcmp(result->raw_v2.data, url, url_len) && result->raw_v2.data[url_len] == ':');
    CHECK(!memcmp(result->raw_v2.data + url_len + 1, secret, 32));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_part(result->secret_parts, "url", url);
    check_part(result->secret_parts, "key", secret);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, result, &reason));
    CHECK(reason && !strcmp(reason, ""));
    free(reason);
}

/* Separate the URL's own azure prefix from the tested key prefix by >40 bytes. */
static void input_for(char *input, size_t size, const char *url, const char *prefix, size_t gap, const char *secret)
{
    size_t at = (size_t)snprintf(input, size, "%s", url);
    CHECK(at < size && gap < size - at && size - at - gap > 82);
    memset(input + at, '\n', 80); at += 80;
    int n = snprintf(input + at, size - at, "%s%*s%s", prefix, (int)gap, "", secret);
    CHECK(n >= 0 && (size_t)n < size - at);
}

static void extraction_case(const br_detector *detector, const char *input, const char *url, const char *secret)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (url ? 1 : 0) && !http.calls && !http.releases);
    if (url) check_result(detector, &results.items[0], url, secret, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], value[96], secret[34];
    const char *prefixes[] = {"azure", "AZURE", "subscription", "SUBSCRIPTION", "key", "monkey"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        input_for(input, sizeof(input), base_url, prefixes[i], 1, key);
        extraction_case(detector, input, base_url, key);
    }
    /* Both dots in .azure-api.net are source regex wildcards, not literals.
     * The shorter azure alternative ends 48 bytes before the key here. */
    input_for(input, sizeof(input), base_url, "Qazure-apiXnet", 40, key);
    extraction_case(detector, input, base_url, key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        input_for(input, sizeof(input), base_url, "subscription", gap, key);
        extraction_case(detector, input, gap == 40 ? base_url : NULL, key);
    }
    input_for(input, sizeof(input), base_url, "key\r\n", 0, key);
    extraction_case(detector, input, base_url, key);
    extraction_case(detector, "", NULL, NULL);
    extraction_case(detector, base_url, NULL, NULL);
    snprintf(input, sizeof(input), "key %s", key);
    extraction_case(detector, input, NULL, NULL);

    const char *urls[] = {
        "https://ab.azure-api.net", "https://a-0.azure-api.net", "https://a.azure-api.net",
        "HTTPS://ab.azure-api.net", "http://ab.azure-api.net", "https://Ab.azure-api.net",
        "https://ab.Azure-api.net", "https://ab.azure-api.NET", "https://-ab.azure-api.net",
        "https://ab-.azure-api.net", "https://a_b.azure-api.net",
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i) {
        input_for(input, sizeof(input), urls[i], "key", 1, key);
        extraction_case(detector, input, i < 2 ? urls[i] : NULL, key);
    }
    for (size_t label = 50; label <= 51; ++label) {
        memcpy(value, "https://", 8);
        memset(value + 8, 'a', label);
        memcpy(value + 8 + label, ".azure-api.net", sizeof(".azure-api.net"));
        input_for(input, sizeof(input), value, "key", 1, key);
        extraction_case(detector, input, label == 50 ? value : NULL, key);
    }
    const char *suffixes[] = {".evil", "z", "/path?query=yes"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(value, sizeof(value), "%s%s", base_url, suffixes[i]);
        input_for(input, sizeof(input), value, "key", 1, key);
        extraction_case(detector, input, base_url, key); /* No invented right boundary. */
    }
    snprintf(value, sizeof(value), "prefix%s", base_url);
    input_for(input, sizeof(input), value, "key", 1, key);
    extraction_case(detector, input, base_url, key);
    memset(secret, '-', 32); secret[32] = '\0';
    input_for(input, sizeof(input), base_url, "key", 1, secret);
    extraction_case(detector, input, base_url, secret); /* Hyphens, not hex or an entropy rule. */
    memcpy(secret, key, sizeof(key)); secret[12] = '_';
    input_for(input, sizeof(input), base_url, "key", 1, secret);
    extraction_case(detector, input, NULL, NULL);
    memcpy(secret, key, 32); secret[32] = 'X'; secret[33] = '\0';
    input_for(input, sizeof(input), base_url, "key", 1, secret);
    extraction_case(detector, input, base_url, key); /* First 32, no trailing boundary. */
    snprintf(value, sizeof(value), "_%s_", key);
    input_for(input, sizeof(input), base_url, "key", 1, value);
    extraction_case(detector, input, base_url, key); /* No leading boundary either. */
    secret[31] = '\0';
    input_for(input, sizeof(input), base_url, "key", 1, secret);
    extraction_case(detector, input, NULL, NULL);

    input_for(input, sizeof(input), base_url, "key", 1, key);
    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    const char *terms[] = {"example"};
    char *reason = NULL;
    CHECK(br_known_false_positive((br_slice){results.items[0].raw.data, results.items[0].raw.len}, terms, 1, true, &reason));
    free(reason); reason = NULL;
    bool filtered = detector->false_positive ? detector->false_positive(detector, &results.items[0], &reason) :
        br_known_false_positive((br_slice){results.items[0].raw.data, results.items[0].raw.len}, terms, 1, true, &reason);
    CHECK(!filtered && reason && !strcmp(reason, ""));
    free(reason);
    br_results_clear(&results);
}

typedef struct { const char *urls[2], *keys[2]; size_t nurls, nkeys; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->nurls * expected->nkeys);
    CHECK(http->releases + 1 == http->calls);
    size_t u = (http->calls - 1) / expected->nkeys, k = (http->calls - 1) % expected->nkeys;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1019 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    char url[96];
    snprintf(url, sizeof(url), "%s/echo/resource", expected->urls[u]);
    CHECK(!strcmp(request->url, url));
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Ocp-Apim-Subscription-Key") && !strcmp(request->headers[1].value, expected->keys[k]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog apim-subscription-test"));
}

static void product(const br_detector *detector)
{
    const char *urls[] = {"https://firstsvc.azure-api.net", "https://secondsvc.azure-api.net"};
    const char *keys[] = {key, second_key};
    char input[512];
    snprintf(input, sizeof(input), "%s/path\n%s\n%s?other\nkey %s\nsubscription %s\nkey %s",
             urls[0], urls[1], urls[0], key, second_key, key);
    expected_requests expected = {.urls = {urls[0], urls[1]}, .keys = {key, second_key}, .nurls = 2, .nkeys = 2};
    static const unsigned char body[] = "not parsed JSON/XML";
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = "ignored read failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apim-subscription-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify != 0, input, strlen(input));
        CHECK(results.len == 4 && http.calls == (verify ? 4 : 0) && http.releases == http.calls);
        for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 2; ++k)
            check_result(detector, &results.items[u * 2 + k], urls[u], keys[k], verify != 0, NULL);
        br_results_clear(&results);
    } /* Even ALL-200 responses must retain every URL-major pair. */
    const char *errors[] = {"no such host", "lookup synthetic: no such host", "unrelated transport failure"};
    for (size_t e = 0; e < 3; ++e) {
        http = (test_http){.response = {.status = 200}, .send_rc = -1, .send_error = errors[e],
                           .inspect = inspect_request, .user = &expected};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
        for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 2; ++k)
            check_result(detector, &results.items[u * 2 + k], urls[u], keys[k], false, NULL);
        br_results_clear(&results);
    } /* Repeated literal DNS errors never populate a cache or suppress a pair. */
    http.calls = http.releases = 0;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    br_results_clear(&results);
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[512];
    input_for(input, sizeof(input), base_url, "key", 1, key);
    expected_requests expected = {.urls = {base_url}, .keys = {key}, .nurls = 1, .nkeys = 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apim-subscription-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(detector, &results.items[0], base_url, key, verified, error);
    br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 401, 403, 302, 500};
    const unsigned char body[] = {0, 0xff, '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80];
        snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read error"}};
        verify_case(detector, &http, statuses[i] == 200, i < 2 ? NULL : error);
    }
    const char *errors[] = {"no such host", "No such host", "context canceled", "context deadline exceeded", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = -1, .send_error = errors[i]};
        verify_case(detector, &http, false, NULL);
    }
    char input[512];
    input_for(input, sizeof(input), base_url, "key", 1, key);
    br_scan_ctx offline = {0}; /* Never let NULL choose the native transport. */
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(detector, &results.items[0], base_url, key, false, NULL);
    br_results_clear(&results);
    /* In contrast, nil context is a request-CREATION failure and is retained. */
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(detector, &results.items[0], base_url, key, false, "net/http: nil Context");
    br_results_clear(&results);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(detector, &results.items[0], base_url, key, false, NULL);
    br_results_clear(&results);
}

static void setter_resource_failure(const br_detector *detector)
{
    const char url[] = "https://setter-oom.azure-api.net";
    char input[512];
    input_for(input, sizeof(input), url, "key", 1, key);
    expected_requests expected = {.urls = {url}, .keys = {key}, .nurls = 1, .nkeys = 1};
    test_http http = {.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apim-subscription-test"};
    br_slice source = {(const unsigned char *)input, strlen(input)};
    br_results first = {0}, retry = {0};
    char *error = NULL, *retry_error = NULL;
    fail_status_503_strdup = true;
    int rc = detector->scan(detector, &ctx, true, source, &first, &error);
    CHECK(!fail_status_503_strdup);
    CHECK(http.calls == 1 && http.releases == 1);
    http.calls = http.releases = 0;
    int retry_rc = detector->scan(detector, &ctx, true, source, &retry, &retry_error);
    if (!rc || first.len || !http.calls || retry.len != 1)
        fprintf(stderr, "503 setter OOM: first rc=%d findings=%zu; retry rc=%d calls=%zu findings=%zu\n",
                rc, first.len, retry_rc, http.calls, retry.len);
    CHECK(rc != 0 && error && !strcmp(error, "cannot verify Azure API Management subscription candidate") && !first.len);
    CHECK(!retry_rc && !retry_error && retry.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(detector, &retry.items[0], url, key, false, status_503);
    free(error); free(retry_error);
    br_results_clear(&first); br_results_clear(&retry);
}

int main(void)
{
    test_secret(key, 32, 0); key[0] = 'A'; key[15] = '-';
    test_secret(second_key, 32, 13); second_key[0] = 'Z'; second_key[16] = '-';
    const br_detector *detector = descriptor();
    extraction(detector);
    product(detector);
    verification(detector);
    setter_resource_failure(detector);
    return test_finish("AzureAPIManagementSubscriptionKey");
}
