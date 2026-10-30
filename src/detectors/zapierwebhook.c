/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zapierwebhook/zapierwebhook.go.
 * The defaults constructor is commented out, so this scanner is not enabled. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zapier_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zapier_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    const char *cause = NULL;
    char *transport_error = NULL;
    br_http_response response = {0};
    static const char prefix[] = "https://hooks.zapier.com/hooks/catch/";
    /* The captured key already includes the catch prefix, so the request URL
     * repeats it. The complete URL is built before NewRequestWithContext. */
    if (key.len > SIZE_MAX - sizeof(prefix))
        return zapier_fail(error, "cannot build ZapierWebhook URL");
    char *url = malloc(sizeof(prefix) - 1 + key.len + 1);
    if (!url) return zapier_fail(error, "cannot build ZapierWebhook URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        br_go_url_parts parts = {0};
        br_go_url_error parsed = {0};
        char *fatal = NULL;
        int parsed_rc = br_go_url_parse((br_slice){(const unsigned char *)url, strlen(url)},
                                        &parts, &parsed, &fatal);
        if (parsed_rc != 0 || parsed.kind != BR_GO_URL_OK) {
            zapier_fail(error, fatal ? fatal : "invalid ZapierWebhook URL");
            free(fatal);
            br_go_url_clear(&parts);
            free(url);
            return -1;
        }
        br_go_url_clear(&parts);
        const br_http_request request = {
            .method = "POST", .url = url, .profile = BR_HTTP_DETECTOR_PUBLIC,
            .detector_type = result->detector_type,
        };
        /* 200 verifies. 401 is unverified with a nil error. Every other status
         * is an unexpected-status error. Body read errors are ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
            cause = transport_error;
        } else if (response.status == 200) {
            result->verified = true;
        } else if (response.status != 401) {
            char status[64];
            snprintf(status, sizeof(status), "unexpected status code: %d", response.status);
            cause = status;
            br_slice secret = {key.data, key.len};
            int rc = br_result_set_verification_error(result, cause, &secret, 1);
            br_http_release(ctx, &response);
            free(transport_error);
            free(url);
            if (rc != 0) return zapier_fail(error, "cannot set ZapierWebhook verification error");
            return 0;
        }
    }
    br_slice secret = {key.data, key.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(url);
    if (rc != 0) return zapier_fail(error, "cannot set ZapierWebhook verification error");
    return 0;
}

static int zapier_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return zapier_fail(error, "invalid or uninitialized ZapierWebhook scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Unprefixed. Ordered duplicates stay. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len < 16) {
            zapier_fail(&owned_error, "invalid ZapierWebhook capture");
            rc = -1;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            zapier_fail(&owned_error, "cannot create ZapierWebhook result");
            rc = -1;
        } else if (verify && zapier_verify(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            zapier_fail(&owned_error, "cannot append ZapierWebhook result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const zapier_keywords[] = {"hooks.zapier.com/hooks/catch/"};
static br_detector zapier_detector = {
    .type = 45, .version = 0, .name = "ZapierWebhook", .custom_name = "",
    .description = "Zapier is an automation tool that connects your apps and services. Zapier webhooks can be used to automate workflows by sending HTTP requests to a unique URL.",
    .keywords = zapier_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zapier_scan,
};

int br_zapierwebhook_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zapier_fail(error, "invalid ZapierWebhook detector output");
    *out = NULL;
    if (!zapier_detector.state &&
        br_regex_compile("(https:\\/\\/hooks\\.zapier\\.com\\/hooks\\/catch\\/[A-Za-z0-9\\/]{16})",
                         (br_regex **)&zapier_detector.state, error) != 0)
        return -1;
    *out = &zapier_detector;
    return 0;
}
