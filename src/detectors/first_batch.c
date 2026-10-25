/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/{abstract,abuseipdb,abyssale}. */
#include "first_batch.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int scan_error(char **error, const char *message)
{
    if (error) {
        size_t len = strlen(message) + 1;
        *error = malloc(len);
        if (*error) memcpy(*error, message, len);
    }
    return -1;
}

static int verification_error(br_result *result, const char *cause)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int unexpected_status(br_result *result, int status)
{
    char message[80];
    snprintf(message, sizeof(message), "unexpected HTTP response status %d", status);
    return verification_error(result, message);
}

static int verify_abstract(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://exchange-rates.abstractapi.com/v1/live/?api_key=%s&base=USD", key);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 384,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        /* Upstream only inspects status; even a failed body read is irrelevant. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static bool contains_ip_address(br_slice body)
{
    static const unsigned char needle[] = "ipAddress";
    const size_t len = sizeof(needle) - 1;
    if (body.len < len) return false;
    for (size_t i = 0; i <= body.len - len; ++i) {
        if (memcmp(body.data + i, needle, len) == 0) return true;
    }
    return false;
}

static int verify_abuseipdb(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Key", key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 521,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200:
            if (response.body_error) {
                rc = verification_error(result, response.body_error);
            } else {
                /* This intentionally accepts malformed JSON containing these bytes. */
                result->verified = contains_ip_address(response.body);
            }
            break;
        case 401: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int verify_abyssale(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"x-api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.abyssale.com/ready",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 239,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 403: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_abstract(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abstract, error);
}

static int scan_abuseipdb(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abuseipdb, error);
}

static int scan_abyssale(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abyssale, error);
}

static const char *const abstract_keywords[] = {"abstract"};
static const char *const abuseipdb_keywords[] = {"abuseipdb"};
static const char *const abyssale_keywords[] = {"abyssale"};

static br_detector abstract_detector = {
    .type = 384, .version = 0, .name = "Abstract", .custom_name = "",
    .description = "Abstract API provides various services including exchange rates. The API keys can be used to access these services and retrieve data.",
    .keywords = abstract_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abstract,
};

static br_detector abuseipdb_detector = {
    .type = 521, .version = 0, .name = "AbuseIPDB", .custom_name = "",
    .description = "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses for abusive activities.",
    .keywords = abuseipdb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abuseipdb,
};

static br_detector abyssale_detector = {
    .type = 239, .version = 0, .name = "Abyssale", .custom_name = "",
    .description = "Abyssale is a service offering various API functionalities for marketing automation and services such as images and ad campaigns. Abyssale API keys can be used to access and interact with this data.",
    .keywords = abyssale_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abyssale,
};

/* Keep upstream default-list order, with its commented Abstract available directly. */
static const br_detector *const implemented[] = {
    &abyssale_detector, &abstract_detector, &abuseipdb_detector,
};

int br_first_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return scan_error(error, "invalid first-batch outputs");
    if (br_key_pattern_init(&abyssale_detector, "\\b([a-z0-9A-Z]{40})\\b", error) != 0 ||
        br_key_pattern_init(&abstract_detector, "\\b([0-9a-z]{32})\\b", error) != 0 ||
        br_key_pattern_init(&abuseipdb_detector, "\\b([a-z0-9]{80})\\b", error) != 0)
        return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_first_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == abyssale_detector.type || detector->type == abuseipdb_detector.type;
}
