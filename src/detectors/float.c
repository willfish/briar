/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/float/float.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int float_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is constructor skip, not rejection. Every mixed shared send-domain
 * failure instead retains this original false finding, without setter/classifier. */
static bool float_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    /* Headers follow construction. Exact 59..60-byte ASCII grammar needs at
     * most 67 auth bytes plus NUL, no formatter/heap copy/cap/failure seam. */
    char authorization[68];
    memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, key.data, key.len); authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Authorization", authorization},
        {"User-Agent", "TruffleHog3 (example@example.com)"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.float.com/v3/people",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Source CustomTransport always Header.Adds common UA after provider UA.
     * Leave the shared append intact: do not override, coalesce or bypass it.
     * All 2xx verify; all bodies/read errors, even empty non-NULL, are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack auth lives through synchronous send AND release. Source
     * scan-defers Close; ABI1 eagerly buffers/releases even failed sends. Logical
     * injected duplicate UAs do NOT prove native Go wire serialization. Full
     * Reader/deferred-close/native-wire/client/regexp and global source/engine/
     * output parity remain partial. Keep shared native guards unchanged. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int float_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return float_fail(error, "invalid or uninitialized Float scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i); bool keep = true;
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates, with
         * no Base64/token validation, local filtering, cache or invented metadata.
         * Owned finding resources precede constructor skips/send suppression. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = float_fail(&owned_error, "cannot create Float result");
        if (rc == 0 && verify) keep = float_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = float_fail(&owned_error, "cannot append Float result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const float_keywords[] = {"float"};
static br_detector float_detector = {
    .type = 249, .version = 0, .name = "Float", .custom_name = "",
    .description = "Float is a resource management software used for planning and scheduling projects. Float API keys can be used to access and modify project data and schedules.",
    .keywords = float_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = float_scan,
};

int br_float_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return float_fail(error, "invalid Float detector output");
    *out = NULL;
    /* Only LEADING word boundary. There is no end boundary, EOF assertion or
     * padding validation beyond the literal '=' and source 42..43 class bytes. */
    if (br_key_pattern_init(&float_detector, "\\b([a-f0-9]{16}[A-Za-z0-9+/]{42,43}=)", error) != 0) return -1;
    *out = &float_detector;
    return 0;
}
