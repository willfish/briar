/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paperform/paperform.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char paperform_url[] = "https://api.paperform.co/v1/forms";

static int paperform_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* 0 publishes, including a failed send. -1 is fatal before send and releases nothing. */
static int send_paperform(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Bearer plus the complete key. A 1000-character key must not meet a small buffer. */
    if (!key.data || key.len > SIZE_MAX - 8)
        return paperform_fail(error, "invalid Paperform capture");
    char *authorization = malloc(key.len + 8);
    if (!authorization)
        return paperform_fail(error, "out of memory formatting Paperform authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[key.len + 7] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = paperform_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies. Do not read the body or publish a cause. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return 0;
}

static int scan_paperform(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return paperform_fail(error, "invalid or uninitialized Paperform scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* FindAll runs before a nil drop, including verify set and ctx NULL.
     * Any nonzero, including +1, is fatal before that drop. */
    int capture_rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    int rc = capture_rc == 0 ? 0 : -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice captured = br_captures_at(&keys, i);
        int finding_rc = br_finding_key_bytes(&result, detector->type, captured, "key");
        if (finding_rc != 0)
            rc = paperform_fail(&owned_error, "out of memory creating detector result");
        else if (verify && !ctx) {
            /* NewRequestWithContext(nil) drops only this candidate.
             * No Authorization, send, release, or append. */
            br_result_clear(&result);
            continue;
        } else if (verify && send_paperform(ctx, captured, &result, &owned_error) != 0)
            rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = paperform_fail(&owned_error, "out of memory appending detector result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const paperform_keywords[] = {"paperform"};
static br_detector paperform_detector = {
    .type = 791, .version = 0, .name = "Paperform", .custom_name = "",
    .description = "An API for building and creating forms. API keys could be used to read proprietary or not public form data",
    .keywords = paperform_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_paperform,
};

int br_paperform_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return paperform_fail(error, "invalid Paperform detector output");
    *out = NULL;
    if (br_key_pattern_init(&paperform_detector, "\\b([a-z0-9A-Z-._]{850,1000})\\b", error) != 0)
        return -1;
    *out = &paperform_detector;
    return 0;
}
