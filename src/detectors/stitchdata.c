/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/stitchdata/stitchdata.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int stitchdata_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void stitchdata_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[48];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 35);
    authorization[42] = '\0';
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.stitchdata.com/v4/sources",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int stitchdata_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return stitchdata_fail(error, "invalid or uninitialized Stitchdata scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 35) rc = stitchdata_fail(&owned_error, "invalid Stitchdata capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = stitchdata_fail(&owned_error, "cannot create Stitchdata result");
        else if (verify && !ctx) keep = false;
        else if (verify) stitchdata_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = stitchdata_fail(&owned_error, "cannot append Stitchdata result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const stitchdata_keywords[] = {"stitchdata"};
static br_detector stitchdata_detector = {
    .type = 591, .version = 0, .name = "Stitchdata", .custom_name = "",
    .description = "Stitchdata is a cloud ETL service for consolidating data from various sources into a data warehouse. Stitchdata API keys can be used to manage and automate data pipelines.",
    .keywords = stitchdata_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = stitchdata_scan,
};

int br_stitchdata_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return stitchdata_fail(error, "invalid Stitchdata detector output");
    *out = NULL;
    if (br_key_pattern_init(&stitchdata_detector, "\\b([0-9a-z_]{35})\\b", error) != 0) return -1;
    *out = &stitchdata_detector;
    return 0;
}
