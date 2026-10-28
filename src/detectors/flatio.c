/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flatio/flatio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int flatio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void flatio_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Constructor's known nil-context skip has passed. Accept FIRST, then the
     * complete bounded Bearer value: 7 + KEY128 + NUL, no formatter/heap copy. */
    br_header headers[2] = {{"Accept", "application/json"}};
    char authorization[136];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 129);
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.flat.io/v2/me", .profile = BR_HTTP_SANE,
        .headers = headers, .nheaders = 2, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding without setter/classifier. All successful-send 2xx verify;
     * response contents and read errors are deliberately ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Full stack authorization lives through send AND release. Source defers
     * Close to scan end; ABI1 eagerly reads/releases even failures. Reader,
     * native/private client, regexp and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int flatio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flatio_fail(error, "invalid or uninitialized FlatIO scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates and
         * lower-alphanumeric captures, with no validation/filter/cache. Own
         * finding resources precede the constructor's ordinary nil-context skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = flatio_fail(&owned_error, "cannot create FlatIO result");
        else if (!verify || ctx) {
            if (verify) flatio_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = flatio_fail(&owned_error, "cannot append FlatIO result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flatio_keywords[] = {"flat"};
static br_detector flatio_detector = {
    .type = 501, .version = 0, .name = "FlatIO", .custom_name = "",
    .description = "FlatIO is a music notation software. FlatIO keys can be used to access and modify musical scores and related data.",
    .keywords = flatio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flatio_scan,
};

int br_flatio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flatio_fail(error, "invalid FlatIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&flatio_detector, "\\b([0-9a-z]{128})\\b", error) != 0) return -1;
    *out = &flatio_detector;
    return 0;
}
