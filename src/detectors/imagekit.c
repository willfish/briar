/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/imagekit/imagekit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { IMAGEKIT_ABORT = -1, IMAGEKIT_KEEP = 0, IMAGEKIT_DROP = 1 } imagekit_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static imagekit_outcome verify_imagekit(const br_scan_ctx *ctx, br_slice key,
                                        br_result *result, char **error)
{
    br_http_request request = {
        .method = "GET", .url = "https://api.imagekit.io/v1/files",
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    /* The fixed NewRequestWithContext can reject only nil context. Do not
     * reach SetBasicAuth until after that drop; every encoder nonzero is fatal. */
    if (!ctx) return IMAGEKIT_DROP;
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return IMAGEKIT_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    request.headers = headers;
    request.nheaders = 1;
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses the entire mixed shared setup/Do error domain, never
     * sets a verification error and ignores bodies/read failures at every status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* Provider auth/captures survive ordinary release. Synthesized ABI1 request
     * headers and UA live only through send return, not through this release. */
    free(send_error);
    free(authorization);
    return IMAGEKIT_KEEP;
}

static int scan_imagekit(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Imagekit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        imagekit_outcome outcome = IMAGEKIT_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op on this alphabet. Keep occurrences and 36-byte
         * prefixes, including contextual '=' starts; there is no end boundary. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Imagekit finding");
            outcome = IMAGEKIT_ABORT;
        } else if (verify) {
            outcome = verify_imagekit(ctx, key, &result, &owned_error);
        }
        if (outcome == IMAGEKIT_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Imagekit finding");
            outcome = IMAGEKIT_ABORT;
        }
        br_result_clear(&result);
        if (outcome == IMAGEKIT_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"imagekit"};
static br_detector imagekit = {
    .type = 250, .version = 0, .name = "Imagekit", .custom_name = "",
    .description = "Imagekit is a real-time image optimization and transformation service. Imagekit keys can be used to access and manipulate images on the platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_imagekit,
};

int br_imagekit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Imagekit detector output");
    *out = NULL;
    if (br_key_pattern_init(&imagekit, "\\b([a-zA-Z0-9_=]{36})", error) != 0) return -1;
    *out = &imagekit;
    return 0;
}
