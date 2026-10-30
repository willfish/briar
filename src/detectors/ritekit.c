/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ritekit/ritekit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ritekit_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void ritekit_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int ritekit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ritekit_fail(error, "invalid or uninitialized RiteKit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        char url[128];
        if (key.len != 44) rc = ritekit_fail(&owned_error, "invalid RiteKit capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ritekit_fail(&owned_error, "cannot create RiteKit result");
        else if (verify) {
            int n = snprintf(url, sizeof(url),
                             "https://api.ritekit.com/v1/stats/multiple-hashtags?tags=hello&client_id=%s",
                             keys.items[i]);
            if (n < 0 || (size_t)n >= sizeof(url))
                rc = ritekit_fail(&owned_error, "cannot create RiteKit URL");
            else if (!ctx) keep = false; /* URL is complete before the constructor skip. */
            else ritekit_verify(ctx, url, &result);
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ritekit_fail(&owned_error, "cannot append RiteKit result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ritekit_keywords[] = {"ritekit"};
static br_detector ritekit_detector = {
    .type = 461, .version = 0, .name = "RiteKit", .custom_name = "",
    .description = "RiteKit is a social media toolkit that provides various APIs for managing social media content and analytics. RiteKit API keys can be used to access and manage social media data.",
    .keywords = ritekit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ritekit_scan,
};

int br_ritekit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ritekit_fail(error, "invalid RiteKit detector output");
    *out = NULL;
    if (br_key_pattern_init(&ritekit_detector, "\\b([0-9a-f]{44})\\b", error) != 0) return -1;
    *out = &ritekit_detector;
    return 0;
}
