/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/impala/impala.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int impala_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void impala_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* NewRequestWithContext has succeeded before Header.Add. Captures already
     * have a trailing NUL, so the original key needs no fallible projection. */
    const br_header headers[] = {
        {"X-Api-Key", (const char *)key.data}, /* Go canonicalizes x-api-key. */
    };
    const br_http_request request = {
        .method = "GET", .url = "https://sandbox.impala.travel/v1/bookings",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses every Do error. Shared setup failures occupy the same
     * mixed domain; do not classify diagnostics or set a verification error. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors are ignored at every status. Provider originals live
     * through ordinary release; synthesized headers/UA only through send.
     * Eager release does not reproduce source's scan-deferred body closes. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int impala_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return impala_fail(error, "invalid or uninitialized Impala scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* TrimSpace is a no-op on this ASCII alphabet. Keep original occurrences
     * and duplicates, in source order, without validation or filtering. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 46)
            rc = impala_fail(&owned_error, "invalid Impala capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = impala_fail(&owned_error, "cannot create Impala result");
        if (rc == 0 && verify) {
            /* Finding construction precedes the nil-context constructor drop;
             * headers are assembled only after that constructor succeeds. */
            if (!ctx) keep = false;
            else impala_verify(ctx, key, &result);
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = impala_fail(&owned_error, "cannot append Impala result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const impala_keywords[] = {"impala"};
static br_detector impala_detector = {
    .type = 509, .version = 0, .name = "Impala", .custom_name = "",
    .description = "Impala is a travel API service used for managing bookings and reservations. Impala API keys can be used to access and modify booking data.",
    .keywords = impala_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = impala_scan,
};

int br_impala_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return impala_fail(error, "invalid Impala detector output");
    *out = NULL;
    if (br_key_pattern_init(&impala_detector, "\\b([0-9A-Za-z_]{46})\\b", error) != 0)
        return -1;
    *out = &impala_detector;
    return 0;
}
