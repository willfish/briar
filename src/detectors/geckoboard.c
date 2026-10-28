/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geckoboard/geckoboard.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int geckoboard_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool geckoboard_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* NewRequestWithContext failure skips this occurrence. */
    /* The grammar fixes the complete literal Basic TOKEN value at 50 bytes.
     * This is deliberately NOT Base64 credentials or TOKEN plus a colon. */
    char authorization[51];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, key.data, 44);
    authorization[50] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.geckoboard.com/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/allocation/Do error domain, without a
     * diagnostic classifier or verification-error setter. Ignore body reads. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrowed authorization remains live through synchronous send AND release.
     * ABI1 eagerly releases rather than reproducing scan-deferred Body.Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int geckoboard_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return geckoboard_fail(error, "invalid or uninitialized Geckoboard scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Original occurrences, including duplicates; TrimSpace is a grammar no-op.
     * Finding resources precede constructor skip and ordinary send suppression. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = geckoboard_fail(&owned_error, "cannot create Geckoboard result");
        if (rc == 0 && verify) keep = geckoboard_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = geckoboard_fail(&owned_error, "cannot append Geckoboard result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const geckoboard_keywords[] = {"geckoboard"};
static br_detector geckoboard_detector = {
    .type = 696, .version = 0, .name = "Geckoboard", .custom_name = "",
    .description = "Geckoboard is a data visualization tool that allows users to create real-time dashboards. Geckoboard API keys can be used to access and modify these dashboards.",
    .keywords = geckoboard_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = geckoboard_scan,
};

int br_geckoboard_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return geckoboard_fail(error, "invalid Geckoboard detector output");
    *out = NULL;
    if (br_key_pattern_init(&geckoboard_detector, "\\b([a-zA-Z0-9]{44})\\b", error) != 0)
        return -1;
    *out = &geckoboard_detector;
    return 0;
}
