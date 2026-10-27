/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dailyco/dailyco.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int dailyco_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void dailyco_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The caller already skipped the nil-context constructor error. Only now
     * prepare the complete 71-byte Bearer value plus NUL, live through both
     * synchronous send and release. The pattern guarantees 64 ASCII hex bytes. */
    char authorization[72];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 64);
    authorization[71] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.daily.co/v1/rooms",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 585,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines shared setup/allocation
     * and Do failures; suppress that entire domain without cause classification
     * or a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers close-only, never reading/draining. Body/read errors
     * cannot affect status. Eager buffering/release, full native client behavior
     * and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int dailyco_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dailyco_fail(error, "invalid or uninitialized DailyCO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede the constructor skip and auth preparation. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = dailyco_fail(&owned_error, "cannot create DailyCO result");
        if (rc == 0 && verify && !ctx) {
            br_result_clear(&result);
            continue; /* NewRequestWithContext's known nil-context error. */
        }
        if (rc == 0 && verify) dailyco_verify(ctx, key, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = dailyco_fail(&owned_error, "cannot append DailyCO result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dailyco_keywords[] = {"daily"};
/* Upstream defaults comments out this constructor. The direct factory does not
 * authorize default registration or resurrection through CLI selectors. */
static br_detector dailyco_detector = {
    .type = 585, .version = 0, .name = "DailyCO", .custom_name = "",
    .description = "DailyCO is a video calling service that provides APIs to create and manage video calls. The API keys can be used to access and control these video call services.",
    .keywords = dailyco_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dailyco_scan,
};

int br_dailyco_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dailyco_fail(error, "invalid DailyCO detector output");
    *out = NULL;
    if (br_key_pattern_init(&dailyco_detector, "\\b([0-9a-f]{64})\\b", error) != 0)
        return -1;
    *out = &dailyco_detector;
    return 0;
}
