/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudflarecakey/cloudflarecakey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cloudflare_ca_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int cloudflare_ca_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    /* Source suppresses request-constructor errors but RETAINS the finding.
     * The fixed URL/method and captured ASCII key leave nil context reachable. */
    if (!ctx) return 0;
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"User-Agent", "curl/7.68.0"},
        {"X-Auth-User-Service-Key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloudflare.com/client/v4/certificates?zone_id=a",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .detector_type = 59,
    };
    /* Source CustomTransport ALWAYS appends TruffleHog after curl/7.68.0.
     * br_http_send supplies that second logical UA; never add it manually.
     * These logical values do not establish native curl duplicate-UA wire parity. */
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    /* Own and redact the cause before releasing borrowed transport state. Only
     * this complete CA key is supplied as a secret. Source ignores body errors. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    /* Source drains/closes in its verifier defer. Eager ABI buffering and native
     * client configuration remain partial, even with per-verification release. */
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) return cloudflare_ca_fail(error, "out of memory recording Cloudflare CA key verification error");
    return 0;
}

static int cloudflare_ca_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cloudflare_ca_fail(error, "invalid or uninitialized Cloudflare CA key scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    /* Source iterates a byte-unique map. First-occurrence order is deterministic
     * here, without changing uniqueness, case, filtering or verification count. */
    int rc = br_captures_find(detector->state, input, &keys, true, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = cloudflare_ca_fail(error, "out of memory creating Cloudflare CA key result");
        else if (verify) rc = cloudflare_ca_verify(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cloudflare_ca_fail(error, "out of memory appending Cloudflare CA key result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cloudflare_ca_keywords[] = {"cloudflare"};
static br_detector cloudflare_ca_detector = {
    .type = 59, .version = 0, .name = "CloudflareCaKey", .custom_name = "",
    .description = "Cloudflare is a web infrastructure and website security company. "
                   "Cloudflare CA keys can be used to manage SSL/TLS certificates and other security settings.",
    .keywords = cloudflare_ca_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cloudflare_ca_scan,
};

int br_cloudflarecakey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cloudflare_ca_fail(error, "invalid Cloudflare CA key detector output");
    *out = NULL;
    /* DIRECT extraction: dispatch keyword and deprecation comment do not alter
     * the pinned capture or default registry membership. */
    if (!cloudflare_ca_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(v1\\.0-[A-Za-z0-9-]{171})\\b", &pattern, error) != 0) return -1;
        cloudflare_ca_detector.state = pattern;
    }
    *out = &cloudflare_ca_detector;
    return 0;
}
