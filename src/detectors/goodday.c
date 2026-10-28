/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/goodday/goodday.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int goodday_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool goodday_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The constant constructor fails only for a nil context; upstream skips
     * that finding, after constructing its Raw and SecretParts. */
    if (!ctx) return false;
    const br_header headers[] = {{"Gd-Api-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.goodday.work/2.0/users",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The complete shared setup/allocation/Do failure domain is false-kept.
     * Body bytes and read errors are not inspected at any status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int goodday_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return goodday_fail(error, "invalid or uninitialized GoodDay scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original nonoverlapping occurrences, including duplicates.
     * TrimSpace cannot change this capture grammar. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = goodday_fail(&owned_error, "cannot create GoodDay result");
        if (rc == 0 && verify) keep = goodday_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = goodday_fail(&owned_error, "cannot append GoodDay result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    /* The provider's original key values remain alive through every release;
     * ordinary shared effective headers/User-Agent end at send return. */
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const goodday_keywords[] = {"goodday"};
static br_detector goodday_detector = {
    .type = 654, .version = 0, .name = "GoodDay", .custom_name = "",
    .description = "GoodDay is a project management tool. GoodDay API tokens can be used to access and manage project data.",
    .keywords = goodday_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = goodday_scan,
};

int br_goodday_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return goodday_fail(error, "invalid GoodDay detector output");
    *out = NULL;
    if (br_key_pattern_init(&goodday_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &goodday_detector;
    return 0;
}
