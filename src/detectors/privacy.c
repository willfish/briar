/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/privacy/privacy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { PV_ABORT = -1, PV_KEEP = 0, PV_DROP = 1 } pv_outcome;

static int pv_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static pv_outcome pv_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return PV_DROP;
    if (key.len != 36) return pv_fail(error, "unexpected Privacy key length"), PV_ABORT;
    char authorization[8 + 36 + 1];
    memcpy(authorization, "api-key ", 8);
    memcpy(authorization + 8, key.data, 36);
    authorization[44] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.privacy.com/v1/card?page=1&page_size=50",
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
            rc = pv_fail(error, "cannot format Privacy verification status");
        else cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    if (rc == 0 && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = pv_fail(error, "cannot set Privacy verification error");
    /* Stack api-key value remains live through release. 401 sets no cause. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc == 0 ? PV_KEEP : PV_ABORT;
}

static int pv_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pv_fail(error, "invalid or uninitialized Privacy scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        pv_outcome outcome = PV_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pv_fail(&owned_error, "cannot create Privacy result");
        else if (verify)
            outcome = pv_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && outcome == PV_ABORT) rc = -1;
        if (rc == 0 && outcome == PV_KEEP && br_results_push(out, &result) != 0)
            rc = pv_fail(&owned_error, "cannot append Privacy result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pv_keywords[] = {"privacy"};
static br_detector pv_detector = {
    .type = 938, .version = 0, .name = "Privacy", .custom_name = "",
    .description = "Privacy provides virtual cards for secure online payments. Privacy API keys can be used to manage and create these virtual cards.",
    .keywords = pv_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pv_scan,
};

int br_privacy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pv_fail(error, "invalid Privacy detector output");
    *out = NULL;
    if (br_key_pattern_init(&pv_detector,
            "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
            error) != 0)
        return -1;
    *out = &pv_detector;
    return 0;
}
