/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/detectlanguage/detectlanguage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int detectlanguage_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void detectlanguage_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The caller has passed the known nil-context constructor skip. The exact
     * 32-byte ASCII capture needs no escaping or fallible auth formatting.
     * Borrow the complete 39-byte Bearer value plus NUL through send AND release. */
    char authorization[7 + 32 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://ws.detectlanguage.com/0.2/user/status",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire mixed shared setup/allocation/Do failure domain,
     * without a verification-error setter or diagnostic-stage classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * never affect status. Eager buffering/release, full native/private client,
     * Reader/regexp behavior and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int detectlanguage_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return detectlanguage_fail(error, "invalid or uninitialized DetectLanguage scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key cannot represent constructor skip: do not append and then
     * remove a finding to simulate it. Keep every source occurrence instead. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Finding resources precede the known constructor
         * skip, which itself precedes Authorization preparation. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = detectlanguage_fail(&owned_error, "cannot create DetectLanguage result");
        else if (!verify || ctx) {
            if (verify) detectlanguage_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = detectlanguage_fail(&owned_error, "cannot append DetectLanguage result");
        } /* verify && !ctx: source NewRequestWithContext skips this candidate. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const detectlanguage_keywords[] = {"detectlanguage"};
static br_detector detectlanguage_detector = {
    .type = 434, .version = 0, .name = "DetectLanguage", .custom_name = "",
    .description = "DetectLanguage is a language detection API service. The API key can be used to access the language detection functionalities provided by DetectLanguage.",
    .keywords = detectlanguage_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = detectlanguage_scan,
};

int br_detectlanguage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return detectlanguage_fail(error, "invalid DetectLanguage detector output");
    *out = NULL;
    if (br_key_pattern_init(&detectlanguage_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &detectlanguage_detector;
    return 0;
}
