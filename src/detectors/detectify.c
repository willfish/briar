/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/detectify/detectify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int detectify_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void detectify_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The constructor's known nil-context skip precedes this header setup.
     * Borrow the complete NUL-terminated capture through send AND release. */
    const br_header header = {"X-Detectify-Key", key};
    const br_http_request request = {
        .method = "GET", .url = "https://api.detectify.com/rest/v2/assets/",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire shared setup/allocation/Do domain, without a setter
     * or text-stage classifier. Body/read errors never alter the status. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Eager ABI
     * buffering/release, full native client and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int detectify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return detectify_fail(error, "invalid or uninitialized Detectify scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Keep all occurrences, including duplicates.
         * Finding resources must fail before any nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = detectify_fail(&owned_error, "cannot create Detectify result");
        else if (!verify || ctx) {
            if (verify) detectify_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = detectify_fail(&owned_error, "cannot append Detectify result");
        } /* verify && !ctx: skip without header preparation or an artificial append. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const detectify_keywords[] = {"detectify"};
static br_detector detectify_detector = {
    .type = 794, .version = 0, .name = "Detectify", .custom_name = "",
    .description = "Detectify is a web application security scanner that helps identify vulnerabilities in web applications. Detectify API keys can be used to access and manage security scans and findings.",
    .keywords = detectify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = detectify_scan,
};

int br_detectify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return detectify_fail(error, "invalid Detectify detector output");
    *out = NULL;
    if (br_key_pattern_init(&detectify_detector, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &detectify_detector;
    return 0;
}
