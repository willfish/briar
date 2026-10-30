/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/overloop/overloop.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { OL_ABORT = -1, OL_KEEP = 0, OL_DROP = 1 } ol_outcome;

static int ol_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static ol_outcome ol_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Static URL. NewRequestWithContext fails before Header.Set on a nil context. */
    if (!ctx) return OL_DROP;
    const br_header headers[] = {{"Authorization", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.overloop.com/public/v1/users",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = ol_fail(error, "cannot format Overloop verification status");
        else cause = status_error;
    }
    /* 401 is determinately unverified. Redact the raw key, not a bearer prefix. */
    br_slice secret = {result->raw.data, result->raw.len};
    if (rc == 0 && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = ol_fail(error, "cannot set Overloop verification error");
    br_http_release(ctx, &response);
    free(send_error);
    return rc == 0 ? OL_KEEP : OL_ABORT;
}

static int ol_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ol_fail(error, "invalid or uninitialized Overloop scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        ol_outcome outcome = OL_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ol_fail(&owned_error, "cannot create Overloop result");
        else if (verify)
            outcome = ol_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && outcome == OL_ABORT) rc = -1;
        if (rc == 0 && outcome == OL_KEEP && br_results_push(out, &result) != 0)
            rc = ol_fail(&owned_error, "cannot append Overloop result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ol_keywords[] = {"overloop"};
static br_detector ol_detector = {
    .type = 965, .version = 0, .name = "Overloop", .custom_name = "",
    .description = "Overloop is a service that provides API keys for accessing its platform. These keys can be used to interact with the Overloop API to manage and retrieve user data.",
    .keywords = ol_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ol_scan,
};

int br_overloop_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ol_fail(error, "invalid Overloop detector output");
    *out = NULL;
    if (br_key_pattern_init(&ol_detector, "\\b([a-zA-Z_\\-0-9]{50})\\b", error) != 0) return -1;
    *out = &ol_detector;
    return 0;
}
