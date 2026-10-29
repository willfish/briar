/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/holistic/holistic.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int holistic_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int holistic_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, char **error)
{
    /* Finding construction precedes NewRequestWithContext's nil-context drop;
     * Header.Add happens only after that constructor succeeds. */
    if (!ctx) { *keep = false; return 0; }
    const br_header headers[] = {{"X-Api-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.holistic.dev/api/v1/project",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* The whole mixed shared setup/Do failure domain keeps a false finding,
     * including allocation failures. No diagnostic classifier or setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        /* ReadAll precedes every status decision. Even an empty error cause
         * drops the finding; partial bytes and status cannot override it. */
        if (response.body_error) *keep = false;
        else if (!response.body.data && response.body.len)
            rc = holistic_fail(error, "invalid Holistic response body slice");
        else {
            static const unsigned char marker[] = "\"data\":[]";
            bool rejected = br_slice_find(response.body,
                (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && !rejected;
        }
    }
    /* Original URL/header/capture storage survives release, not shared prepared
     * headers/UA. ABI1 releases every attempt: source defers Close only after
     * ReadAll succeeds, so Reader/close timing and source leaks are not copied. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int holistic_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return holistic_fail(error, "invalid or uninitialized Holistic scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* Preserve source occurrences/duplicates. TrimSpace is a no-op for
         * this bounded lowercase-hex capture, not a whole-token validator. */
        if (key.len != 64)
            rc = holistic_fail(&owned_error, "invalid Holistic capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = holistic_fail(&owned_error, "cannot create Holistic result");
        if (rc == 0 && verify)
            rc = holistic_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = holistic_fail(&owned_error, "cannot append Holistic result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const holistic_keywords[] = {"holistic"};
static br_detector holistic_detector = {
    .type = 764, .version = 0, .name = "Holistic", .custom_name = "",
    .description = "Holistic is a service that provides comprehensive project management solutions. Holistic API keys can be used to access and manage project data.",
    .keywords = holistic_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = holistic_scan,
};

int br_holistic_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return holistic_fail(error, "invalid Holistic detector output");
    *out = NULL;
    if (br_key_pattern_init(&holistic_detector, "\\b([0-9a-f]{64})\\b", error) != 0)
        return -1;
    *out = &holistic_detector;
    return 0;
}
