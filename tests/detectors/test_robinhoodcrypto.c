/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <openssl/evp.h>

int br_robinhoodcrypto_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *const *parts = http->user;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://trading.robinhood.com//api/v1/crypto/trading/accounts/"));
    CHECK(request->nheaders == 4 && request->timeout_ms == 5000 && request->detector_type == 996);
    CHECK(!strcmp(request->headers[0].name, "x-api-key") && !strcmp(request->headers[0].value, parts[0]));
    CHECK(!strcmp(request->headers[1].name, "x-signature"));
    CHECK(!strcmp(request->headers[2].name, "x-timestamp"));
    CHECK(request->body.data && !request->body.len);
    unsigned char seed[32];
    memset(seed, 'A', 32);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    unsigned char signature[64];
    size_t length = 64;
    char message[160];
    int n = snprintf(message, sizeof(message), "%s%s/api/v1/crypto/trading/accounts/GET",
                     parts[0], request->headers[2].value);
    CHECK(n > 0);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    CHECK(key && md && EVP_DigestSignInit(md, NULL, NULL, NULL, key) == 1);
    CHECK(EVP_DigestSign(md, signature, &length, (unsigned char *)message, (size_t)n) == 1);
    unsigned char encoded[96];
    int encoded_len = EVP_EncodeBlock(encoded, signature, 64);
    CHECK(encoded_len > 0 && !strcmp(request->headers[1].value, (char *)encoded));
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, name, &value));
    return json_object_get_string(value);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_robinhoodcrypto_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 996 && !strcmp(detector->keywords[0], "rh-api-"));
    const char *api = "rh-api-01234567-89ab-cdef-0123-456789abcdef";
    unsigned char seed[32];
    memset(seed, 'A', 32);
    char private_key[64];
    int n = EVP_EncodeBlock((unsigned char *)private_key, seed, 32);
    CHECK(n == 44);
    char input[160];
    snprintf(input, sizeof(input), "%s %s", api, private_key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    CHECK(found.items[0].raw.len == strlen(api) && !memcmp(found.items[0].raw.data, api, strlen(api)));
    CHECK(found.items[0].raw_v2.len == strlen(api) + strlen(private_key));
    br_results_clear(&found);
    snprintf(input, sizeof(input), "%s %s %s", api, api, private_key);
    br_results unique = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(unique.len == 1);
    br_results_clear(&unique);
    snprintf(input, sizeof(input), "%s aa==", api);
    br_results short_key = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(short_key.len == 1 && !short_key.items[0].verified && !short_key.items[0].verification_error);
    br_results_clear(&short_key);
    br_results short_verified = {0};
    test_http unused = {0};
    br_transport unused_transport = test_transport(&unused);
    br_scan_ctx unused_ctx = {.transport = &unused_transport};
    br_results too_short = test_scan(detector, &unused_ctx, true, input, strlen(input));
    CHECK(too_short.len == 1 && !too_short.items[0].verified && unused.calls == 0);
    CHECK(too_short.items[0].verification_error &&
          strstr(too_short.items[0].verification_error, "private key is too short"));
    br_results_clear(&too_short);
    (void)short_verified;

    snprintf(input, sizeof(input), "%s %s", api, private_key);
    const char *parts[] = {api, private_key};
    const br_header json_headers[] = {{"Content-Type", "application/json"}};
    const char *account = "{\"account_number\":\"A1\",\"status\":\"ok\",\"buying_power\":\"1\",\"buying_power_currency\":\"USD\"}";
    test_http http = {.response = {.status = 200, .headers = json_headers, .nheaders = 1,
                                   .body = {(const unsigned char *)account, strlen(account)}},
                      .inspect = inspect_request, .user = parts};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified && http.calls == 1);
    CHECK(!strcmp(extra(&verified.items[0], "Robinhood Crypto Account Number"), "A1"));
    br_results_clear(&verified);

    const char *kept_null =
        "{\"account_number\":\"A1\\u0000Z\",\"account_number\":null,\"status\":\"ok\","
        "\"buying_power\":\"1\",\"buying_power_currency\":\"USD\"}";
    http.response.body = (br_slice){(const unsigned char *)kept_null, strlen(kept_null)};
    http.calls = http.releases = 0;
    br_results kept = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(kept.len == 1 && kept.items[0].verified && !kept.items[0].verification_error);
    br_json *account_value = NULL;
    CHECK(json_object_object_get_ex(kept.items[0].extra_data, "Robinhood Crypto Account Number", &account_value));
    CHECK(json_object_get_string_len(account_value) == 4);
    CHECK(!memcmp(json_object_get_string(account_value), "A1\0Z", 4));
    br_results_clear(&kept);
    const char *sticky = "{\"account_number\":1,\"account_number\":\"A1\"}";
    http.response.body = (br_slice){(const unsigned char *)sticky, strlen(sticky)};
    http.calls = http.releases = 0;
    br_results sticky_result = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(sticky_result.len == 1 && sticky_result.items[0].verified && !sticky_result.items[0].extra_data);
    CHECK(sticky_result.items[0].verification_error &&
          !strcmp(sticky_result.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field .account_number of type string"));
    br_results_clear(&sticky_result);

    http.response.body = (br_slice){(const unsigned char *)"{", 1};
    http.calls = http.releases = 0;
    br_results incomplete = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(incomplete.len == 1 && incomplete.items[0].verified);
    CHECK(incomplete.items[0].verification_error &&
          !strcmp(incomplete.items[0].verification_error, "unexpected EOF"));
    CHECK(!strstr(incomplete.items[0].verification_error, "failed to obtain additional information"));
    br_results_clear(&incomplete);
    const char *typed = "{\"account_number\":1}";
    http.response.body = (br_slice){(const unsigned char *)typed, strlen(typed)};
    http.calls = http.releases = 0;
    br_results typed_result = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(typed_result.len == 1 && typed_result.items[0].verified);
    CHECK(typed_result.items[0].verification_error &&
          !strcmp(typed_result.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field .account_number of type string"));
    CHECK(!strstr(typed_result.items[0].verification_error, "failed to obtain additional information"));
    br_results_clear(&typed_result);
    http.response.body = (br_slice){(const unsigned char *)account, strlen(account)};

    http.response.nheaders = 0;
    http.response.headers = NULL;
    http.calls = http.releases = 0;
    br_results no_headers = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(no_headers.len == 1 && no_headers.items[0].verified && !no_headers.items[0].extra_data);
    CHECK(!no_headers.items[0].verification_error);
    br_results_clear(&no_headers);

    http.response.status = 403;
    http.calls = http.releases = 0;
    br_results forbidden = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(forbidden.items[0].verified);
    CHECK(!strcmp(extra(&forbidden.items[0], "Explanation"),
                  "Valid credentials without access to Get Crypto Trading Account Details API"));
    br_results_clear(&forbidden);

    const br_header plain[] = {{"Content-Type", "text/plain"}};
    const char *inactive = "  API credential is not active.\n";
    http.response.status = 401;
    http.response.headers = plain;
    http.response.nheaders = 1;
    http.response.body = (br_slice){(const unsigned char *)inactive, strlen(inactive)};
    http.calls = http.releases = 0;
    br_results inactive_result = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(inactive_result.items[0].verified);
    CHECK(!strcmp(extra(&inactive_result.items[0], "Explanation"), "Valid credentials in inactive state"));
    br_results_clear(&inactive_result);

    unsigned char nulled[32];
    nulled[0] = 0;
    memcpy(nulled + 1, "API credential is not active.", 29);
    http.response.body = (br_slice){nulled, 30};
    http.calls = http.releases = 0;
    br_results nul_body = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(nul_body.len == 1 && !nul_body.items[0].verified && !nul_body.items[0].verification_error);
    br_results_clear(&nul_body);
    const char *nbsp = "\xc2\xa0" "API credential is not active.\n";
    http.response.body = (br_slice){(const unsigned char *)nbsp, strlen(nbsp)};
    http.calls = http.releases = 0;
    br_results nbsp_body = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(nbsp_body.items[0].verified);
    CHECK(!strcmp(extra(&nbsp_body.items[0], "Explanation"), "Valid credentials in inactive state"));
    br_results_clear(&nbsp_body);
    http.response.body = (br_slice){(const unsigned char *)inactive, strlen(inactive)};

    http.response.body_error = "read failed";
    http.calls = http.releases = 0;
    br_results read_failed = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(read_failed.len == 1 && !read_failed.items[0].verified);
    CHECK(read_failed.items[0].verification_error &&
          !strcmp(read_failed.items[0].verification_error, "read failed"));
    CHECK(!strstr(read_failed.items[0].verification_error, "failed to read response body"));
    br_results_clear(&read_failed);
    http.response.body_error = NULL;

    http.response.body = (br_slice){(const unsigned char *)"no", 2};
    http.calls = http.releases = 0;
    br_results active = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!active.items[0].verified && !active.items[0].verification_error);
    br_results_clear(&active);

    http.response.status = 500;
    http.response.nheaders = 0;
    http.calls = http.releases = 0;
    br_results unexpected = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!unexpected.items[0].verified);
    CHECK(!strcmp(unexpected.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&unexpected);

    char dial[160];
    snprintf(dial, sizeof(dial), "failed %s %s", api, private_key);
    test_http failed = {.send_rc = 1, .send_error = dial, .inspect = inspect_request, .user = parts};
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    br_results redacted = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(redacted.items[0].verification_error && strstr(redacted.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(redacted.items[0].verification_error, api));
    CHECK(!strstr(redacted.items[0].verification_error, private_key));
    br_results_clear(&redacted);

    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 1 && !nil.items[0].verified);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(!strcmp(nil.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil);
    return test_finish("RobinhoodCrypto");
}
