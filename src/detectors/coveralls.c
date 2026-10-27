/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coveralls/coveralls.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    COVERALLS_ABORT = -1, COVERALLS_KEEP = 0, COVERALLS_SKIP = 1
} coveralls_outcome;

static int coveralls_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static coveralls_outcome coveralls_verify(const br_scan_ctx *ctx, br_slice key,
                                          br_result *result)
{
    /* NewRequestWithContext's known nil-context skip precedes auth preparation. */
    if (!ctx) return COVERALLS_SKIP;
    /* The capture is exactly 37 ASCII bytes: borrow all 43 auth bytes and the
     * NUL on the stack through synchronous send AND release. */
    char authorization[sizeof("token ") + 37];
    memcpy(authorization, "token ", sizeof("token ") - 1);
    memcpy(authorization + sizeof("token ") - 1, key.data, key.len);
    authorization[sizeof(authorization) - 1] = '\0';
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET",
        .url = "https://coveralls.io/api/repos/github/secretscanner02/scanner",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * failures here; suppress the whole domain, without text classification or
     * a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * cannot alter the status decision. Eager ABI release, full native client
     * configuration and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return COVERALLS_KEEP;
}

static int coveralls_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return coveralls_fail(error, "invalid or uninitialized Coveralls scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        coveralls_outcome outcome = COVERALLS_KEEP;
        /* TrimSpace is a no-op. Preserve all occurrences, including duplicates.
         * Finding resources must fail before any known constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            coveralls_fail(&owned_error, "cannot create Coveralls result");
            outcome = COVERALLS_ABORT;
        }
        if (outcome == COVERALLS_KEEP && verify)
            outcome = coveralls_verify(ctx, key, &result);
        if (outcome == COVERALLS_KEEP && br_results_push(out, &result) != 0) {
            coveralls_fail(&owned_error, "cannot append Coveralls result");
            outcome = COVERALLS_ABORT;
        }
        br_result_clear(&result);
        if (outcome == COVERALLS_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const coveralls_keywords[] = {"coveralls"};
static br_detector coveralls_detector = {
    .type = 192, .version = 0, .name = "Coveralls", .custom_name = "",
    .description = "Coveralls is a web service to help you track your code coverage over time, and ensure that all your new code is fully covered. Coveralls tokens can be used to access and modify coverage data.",
    .keywords = coveralls_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = coveralls_scan,
};

int br_coveralls_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return coveralls_fail(error, "invalid Coveralls detector output");
    *out = NULL;
    if (br_key_pattern_init(&coveralls_detector, "\\b([a-zA-Z0-9-]{37})\\b", error) != 0)
        return -1;
    *out = &coveralls_detector;
    return 0;
}
