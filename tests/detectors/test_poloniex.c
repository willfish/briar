/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

int br_poloniex_init(const br_detector **out, char **error);

static const char key[] = "2ELRAUEF-NB06CX0R-ZGXL88HF-BX8B77S6";
static const char other[] = "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD";
static const char secret[] = "d5dc2f6c299bb01895c604f7038c27af9035937823c7c0e8e25c2efe7f6ddd4fb1bb66781f857e6edf539042389e77043396b123c85197676719ef79a420277b";
static const char secret2[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://poloniex.com/tradingApi"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 516);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Key") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "Sign") && strlen(request->headers[2].value) == 128);
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog poloniex-offline"));
    CHECK(request->body.len > 28 && !memcmp(request->body.data, "command=returnBalances&nonce=", 29));
    unsigned char digest[64]; size_t count = 0;
    CHECK(EVP_Q_mac(NULL, "HMAC", NULL, "SHA512", NULL, secret, strlen(secret),
                    request->body.data, request->body.len, digest, sizeof(digest), &count) && count == 64);
    char signature[129];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; ++i) {
        signature[i * 2] = hex[digest[i] >> 4];
        signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[128] = '\0';
    CHECK(!strcmp(request->headers[2].value, signature));
    http->user = (void *)1;
}

static void check_pair(const br_result *result, const char *api, const char *sec)
{
    CHECK(result->detector_type == 516 && !result->verified && !result->verification_error);
    CHECK(result->raw.len == 128 && !memcmp(result->raw.data, sec, 128));
    CHECK(result->raw_v2.len == 35 + 128 && !memcmp(result->raw_v2.data, api, 35));
    CHECK(!memcmp(result->raw_v2.data + 35, sec, 128));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), api));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), sec));
    CHECK(!result->redacted && !result->extra_data && !result->primary_secret.data);
}

int main(void)
{
    CHECK(strlen(key) == 35 && strlen(secret) == 128);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_poloniex_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 516 && !strcmp(detector->name, "Poloniex"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "poloniex"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
        "Poloniex is a cryptocurrency exchange that allows users to trade various digital assets. Poloniex API keys can be used to access and manage account data and perform trading operations."));
    CHECK(br_poloniex_init(NULL, &error) != 0 && error); free(error);
    char input[512];
    snprintf(input, sizeof(input), "poloniex token - '%s'\npoloniex token - '%s'\n", key, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], key, secret); br_results_clear(&results);
    snprintf(input, sizeof(input), "poloniex %s poloniex %s poloniex %s poloniex %s", key, other, secret, secret2);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4);
    check_pair(&results.items[0], key, secret);
    check_pair(&results.items[1], key, secret2);
    check_pair(&results.items[2], other, secret);
    check_pair(&results.items[3], other, secret2);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "poloniex keyword is not close to the real key in the data\n = '%s'\npoloniex %s", key, secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "poloniex %s\npoloniex %s", "2ELRAUEF?NB06CX0R-ZGXL88HF-BX8B77S6", secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "poloniex %s\npoloniex %s", key, secret);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "poloniex-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.user && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0; http.user = NULL;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1; http.send_error = "dial poloniex"; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    return test_finish("Poloniex");
}
