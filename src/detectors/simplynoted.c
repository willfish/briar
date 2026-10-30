/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/simplynoted/simplynoted.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char simplynoted_url[] = "https://api.simplynoted.com/api/products";

static int simplynoted_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int simplynoted_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              bool *keep, char **error)
{
    *keep = false;
    if (key.len < 340 || key.len > 360) return simplynoted_fail(error, "invalid SimplyNoted capture");
    /* Header.Add follows the nil-context continue. Do and close errors stay quiet. */
    if (!ctx) return 0;
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) return simplynoted_fail(error, "cannot allocate SimplyNoted authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = simplynoted_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int simplynoted_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return simplynoted_fail(error, "invalid or uninitialized SimplyNoted scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = simplynoted_fail(&owned_error, "cannot create SimplyNoted result");
        else if (verify && simplynoted_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        else if (keep && br_results_push(out, &result) != 0)
            rc = simplynoted_fail(&owned_error, "cannot append SimplyNoted result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const simplynoted_keywords[] = {"simplynoted"};
static br_detector simplynoted_detector = {
    .type = 661, .version = 0, .name = "SimplyNoted", .custom_name = "",
    .description = "SimplyNoted is a service used for sending personalized handwritten notes. SimplyNoted API keys can be used to access and send these notes programmatically.",
    .keywords = simplynoted_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = simplynoted_scan,
};

int br_simplynoted_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return simplynoted_fail(error, "invalid SimplyNoted detector output");
    *out = NULL;
    if (br_key_pattern_init(&simplynoted_detector, "\\b([a-zA-Z0-9\\S]{340,360})\\b", error) != 0)
        return -1;
    *out = &simplynoted_detector;
    return 0;
}
