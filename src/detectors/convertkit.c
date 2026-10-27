/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/convertkit/convertkit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CONVERTKIT_ABORT = -1, CONVERTKIT_KEEP = 0, CONVERTKIT_SKIP = 1
} convertkit_outcome;

static int convertkit_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static convertkit_outcome convertkit_verify(const br_scan_ctx *ctx, br_slice key,
                                            br_result *result, char **error)
{
    /* The 22-byte ASCII word capture needs no escaping. Borrow the complete
     * bounded URL, including its NUL, through synchronous send AND release. */
    char url[sizeof("https://api.convertkit.com/v3/forms?api_key=") + 22];
    int n = snprintf(url, sizeof(url), "https://api.convertkit.com/v3/forms?api_key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        convertkit_fail(error, "cannot format Convertkit URL");
        return CONVERTKIT_ABORT;
    }
    /* URL preparation precedes NewRequestWithContext's known nil-context skip. */
    if (!ctx) return CONVERTKIT_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * failures here; suppress the whole domain without text classification or
     * a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * cannot alter the status decision. Eager ABI release, full native client
     * configuration and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return CONVERTKIT_KEEP;
}

static int convertkit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return convertkit_fail(error, "invalid or uninitialized Convertkit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        convertkit_outcome outcome = CONVERTKIT_KEEP;
        /* TrimSpace is a no-op. Preserve all occurrences, including duplicates.
         * Finding resources must fail before any known constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            convertkit_fail(&owned_error, "cannot create Convertkit result");
            outcome = CONVERTKIT_ABORT;
        }
        if (outcome == CONVERTKIT_KEEP && verify)
            outcome = convertkit_verify(ctx, key, &result, &owned_error);
        if (outcome == CONVERTKIT_KEEP && br_results_push(out, &result) != 0) {
            convertkit_fail(&owned_error, "cannot append Convertkit result");
            outcome = CONVERTKIT_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CONVERTKIT_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const convertkit_keywords[] = {"convertkit"};
static br_detector convertkit_detector = {
    .type = 225, .version = 0, .name = "Convertkit", .custom_name = "",
    .description = "Convertkit is an email marketing service provider. API keys can be used to access and manage email marketing campaigns and subscriber data.",
    .keywords = convertkit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = convertkit_scan,
};

int br_convertkit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return convertkit_fail(error, "invalid Convertkit detector output");
    *out = NULL;
    if (br_key_pattern_init(&convertkit_detector, "\\b([a-z0-9A-Z_]{22})\\b", error) != 0)
        return -1;
    *out = &convertkit_detector;
    return 0;
}
