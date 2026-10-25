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

static int scan_abuseipdb(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abuseipdb, error);
}

static const char *const abuseipdb_keywords[] = {"abuseipdb"};

static br_detector abuseipdb_detector = {
    .type = 521, .version = 0, .name = "AbuseIPDB", .custom_name = "",
    .description = "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses for abusive activities.",
    .keywords = abuseipdb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abuseipdb,
};

/* Keep upstream default-list order, with its commented Abstract available directly. */
static const br_detector *const implemented[] = {
    &abuseipdb_detector,
};

int br_first_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return scan_error(error, "invalid first-batch outputs");
    if (br_key_pattern_init(&abuseipdb_detector, "\\b([a-z0-9]{80})\\b", error) != 0)
        return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_first_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == abuseipdb_detector.type;
}
