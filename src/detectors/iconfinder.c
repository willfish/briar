/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/iconfinder/iconfinder.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int iconfinder_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's nil-context continue. */
static bool iconfinder_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    /* The fixed URL has no other constructor failure. Assemble the complete
     * Bearer value only after construction; the grammar fixes 64 ASCII bytes. */
    char authorization[sizeof("Bearer ") - 1 + 64 + 1];
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key.data, 64);
    authorization[sizeof(authorization) - 1] = '\0';
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.iconfinder.com/v4/iconsets",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* All mixed shared setup/Do errors retain a false finding without a setter.
     * The source never reads the body, including read errors at every status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider storage survives ordinary release. Synthesized effective
     * request/header-array/UA storage ends at send return under ABI1. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int iconfinder_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return iconfinder_fail(error, "invalid or uninitialized IconFinder scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op for this alphabet. Keep original occurrences and
         * duplicates, constructing each finding before a constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = iconfinder_fail(&owned_error, "cannot create IconFinder result");
        if (rc == 0 && verify) keep = iconfinder_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = iconfinder_fail(&owned_error, "cannot append IconFinder result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const iconfinder_keywords[] = {"iconfinder"};
static br_detector iconfinder_detector = {
    .type = 487, .version = 0, .name = "IconFinder", .custom_name = "",
    .description = "IconFinder is a platform that provides a large collection of icons. IconFinder API keys can be used to access and retrieve icons from the platform.",
    .keywords = iconfinder_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = iconfinder_scan,
};

int br_iconfinder_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return iconfinder_fail(error, "invalid IconFinder detector output");
    *out = NULL;
    if (!iconfinder_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(iconfinder_keywords, 1, "\\b([a-zA-Z0-9]{64})\\b", &regex, error) != 0)
            return -1;
        iconfinder_detector.state = regex;
    }
    *out = &iconfinder_detector;
    return 0;
}
