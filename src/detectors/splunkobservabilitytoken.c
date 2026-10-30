/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/splunkobservabilitytoken/splunkobservabilitytoken.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int splunkobservabilitytoken_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int splunkobservabilitytoken_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return splunkobservabilitytoken_fail(error, "invalid or uninitialized SplunkOberservabilityToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 22 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = splunkobservabilitytoken_fail(&owned_error, "cannot create SplunkOberservabilityToken result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.us1.signalfx.com/v2/dashboard";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = splunkobservabilitytoken_fail(&owned_error, "cannot append SplunkOberservabilityToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const splunkobservabilitytoken_keywords[] = {"splunk"};
static br_detector splunkobservabilitytoken_detector = {
    .type = 128, .version = 0, .name = "SplunkOberservabilityToken", .custom_name = "",
    .description = "Splunk Observability Tokens are used to access and interact with Splunk's observability suite, allowing for monitoring and analyzing application performance and infrastructure.",
    .keywords = splunkobservabilitytoken_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = splunkobservabilitytoken_scan,
};

int br_splunkobservabilitytoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return splunkobservabilitytoken_fail(error, "invalid SplunkOberservabilityToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&splunkobservabilitytoken_detector, "\\b([a-z0-9A-Z]{22})\\b", error) != 0) return -1;
    *out = &splunkobservabilitytoken_detector;
    return 0;
}
