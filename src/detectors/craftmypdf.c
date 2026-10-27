/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/craftmypdf/craftmypdf.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int craftmypdf_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void craftmypdf_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The complete ASCII capture has a trailing NUL. Borrow it through both
     * synchronous send and release, without another key/header allocation. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Api-Key", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.craftmypdf.com/v1/get-account-info",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = 770,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines shared setup/allocation
     * and Do failures; suppress that entire domain without classifying causes
     * or invoking a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers close-only, never reading/draining. Body errors cannot
     * affect status. Eager ABI release, full native client and global parity
     * remain partial. Release once even when the combined send fails. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int craftmypdf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return craftmypdf_fail(error, "invalid or uninitialized CraftMyPDF scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace is a no-op. Keep occurrences, including duplicate keys.
         * Finding resources must succeed before the known constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = craftmypdf_fail(&owned_error, "cannot create CraftMyPDF result");
        if (rc == 0 && verify && !ctx) {
            br_result_clear(&result);
            continue; /* NewRequestWithContext's nil-context constructor error. */
        }
        if (rc == 0 && verify) craftmypdf_verify(ctx, key, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = craftmypdf_fail(&owned_error, "cannot append CraftMyPDF result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const craftmypdf_keywords[] = {"craftmypdf"};
static br_detector craftmypdf_detector = {
    .type = 770, .version = 0, .name = "CraftMyPDF", .custom_name = "",
    .description = "CraftMyPDF is a service for generating PDFs from templates and data. CraftMyPDF API keys can be used to access and manage PDF generation tasks.",
    .keywords = craftmypdf_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = craftmypdf_scan,
};

int br_craftmypdf_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return craftmypdf_fail(error, "invalid CraftMyPDF detector output");
    *out = NULL;
    if (br_key_pattern_init(&craftmypdf_detector, "\\b([0-9a-zA-Z]{35})\\b", error) != 0)
        return -1;
    *out = &craftmypdf_detector;
    return 0;
}
