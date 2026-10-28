/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/happyscribe/happyscribe.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int happyscribe_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void happyscribe_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The fixed URL constructor succeeded before source formats Authorization.
     * The capture grammar bounds the complete value to 7 + 24 bytes. */
    char authorization[32];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 24);
    authorization[31] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.happyscribe.com/api/v1/transcriptions",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole shared setup/Do domain is suppressed, including allocation
     * failures. Source consumes status only, not body bytes or read errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Only original auth/capture/URL storage survives ordinary send return;
     * synthesized headers and User-Agent retain their ABI1 lifetime. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int happyscribe_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return happyscribe_fail(error, "invalid or uninitialized Happyscribe scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences and duplicates; TrimSpace is a grammar no-op. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 24) rc = happyscribe_fail(&owned_error, "invalid Happyscribe capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = happyscribe_fail(&owned_error, "cannot create Happyscribe result");
        else if (verify && !ctx) {
            /* Finding construction precedes nil-context constructor skip. */
            br_result_clear(&result);
            continue;
        } else if (verify) happyscribe_verify(ctx, key, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = happyscribe_fail(&owned_error, "cannot append Happyscribe result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const happyscribe_keywords[] = {"happyscribe"};
static br_detector happyscribe_detector = {
    .type = 507, .version = 0, .name = "Happyscribe", .custom_name = "",
    .description = "Happyscribe is a transcription service that converts audio to text. Happyscribe API keys can be used to access and manage these transcription services.",
    .keywords = happyscribe_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = happyscribe_scan,
};

int br_happyscribe_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return happyscribe_fail(error, "invalid Happyscribe detector output");
    *out = NULL;
    if (br_key_pattern_init(&happyscribe_detector, "\\b([0-9a-zA-Z]{24})\\b", error) != 0)
        return -1;
    *out = &happyscribe_detector;
    return 0;
}
