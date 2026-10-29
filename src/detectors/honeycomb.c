/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/honeycomb/honeycomb.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int honeycomb_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void honeycomb_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Captures own their trailing NUL; borrow the complete key without another
     * projection allocation. The fixed-URL constructor has already succeeded. */
    const br_header headers[] = {{"X-Honeycomb-Team", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.honeycomb.io/1/auth",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/Do failure domain is false-kept, without a
     * verification-error setter. Body bytes and read errors are not consumed. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original URL/header/key/captures survive this release, even on failure.
     * Ordinary ABI1 synthesized headers/UA end at send return; source instead
     * scan-defers Close, which this eager release does not reproduce. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int honeycomb_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return honeycomb_fail(error, "invalid or uninitialized Honeycomb scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve source-order occurrences and duplicates. TrimSpace is a no-op
     * for both alternatives; no semantic key validation or local filtering. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 32 && key.len != 22)
            rc = honeycomb_fail(&owned_error, "invalid Honeycomb capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = honeycomb_fail(&owned_error, "cannot create Honeycomb result");
        if (rc == 0 && verify) {
            /* Finding construction precedes the nil-context constructor drop. */
            if (!ctx) keep = false;
            else honeycomb_verify(ctx, key, &result);
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = honeycomb_fail(&owned_error, "cannot append Honeycomb result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const honeycomb_keywords[] = {"Honeycomb"};
static br_detector honeycomb_detector = {
    .type = 877, .version = 0, .name = "Honeycomb", .custom_name = "",
    .description = "Honeycomb is a tool for introspecting and interrogating production systems to help users understand how their systems work in real-time. Honeycomb API keys can be used to authenticate and interact with the Honeycomb API.",
    .keywords = honeycomb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = honeycomb_scan,
};

int br_honeycomb_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return honeycomb_fail(error, "invalid Honeycomb detector output");
    *out = NULL;
    if (br_key_pattern_init(&honeycomb_detector,
                            "\\b([0-9a-f]{32}|[0-9a-zA-Z]{22})\\b", error) != 0)
        return -1;
    *out = &honeycomb_detector;
    return 0;
}
