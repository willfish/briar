/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nicereply/nicereply.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    NICEREPLY_ABORT = -1,
    NICEREPLY_KEEP = 0,
    NICEREPLY_DROP = 1
} nicereply_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* ABORT is any owned encoder failure, including +1, even with a nil context.
 * DROP is only a successful encode followed by the constructor skip. */
static nicereply_outcome verify_nicereply(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                          char **error)
{
    char *authorization = NULL;
    /* Empty username and the raw key. The helper value already includes Basic. */
    if (br_http_basic_auth((br_slice){0}, key, &authorization, error) != 0) {
        free(authorization);
        return NICEREPLY_ABORT;
    }
    if (!ctx) {
        free(authorization);
        return NICEREPLY_DROP; /* Before prepare, send, and release. Not an attempt. */
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.nicereply.com/v1/users/stats",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int status = response.status;
    /* A reached send stays unverified for every cause, including NULL.
     * Do not invent transport text or call a setter. */
    free(send_error);
    /* Release once while the helper Authorization value is still alive. */
    br_http_release(ctx, &response);
    free(authorization);
    if (sent == 0 && status >= 200 && status < 300) result->verified = true;
    return NICEREPLY_KEEP;
}

static int scan_nicereply(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Nicereply scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keyword is an engine hint. Keep every in-range match, including duplicates. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        nicereply_outcome outcome = NICEREPLY_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Nicereply finding");
            outcome = NICEREPLY_ABORT;
        } else if (verify)
            outcome = verify_nicereply(ctx, key, &result, &owned_error);
        if (outcome == NICEREPLY_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Nicereply finding");
            outcome = NICEREPLY_ABORT;
        }
        br_result_clear(&result);
        if (outcome == NICEREPLY_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"nicereply"};
static br_detector nicereply = {
    .type = 544,
    .version = 0,
    .name = "Nicereply",
    .custom_name = "",
    .description = "Nicereply is a customer satisfaction survey tool. Nicereply API keys can be used to access and manage survey data and user statistics.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_nicereply,
};

int br_nicereply_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Nicereply detector output");
    *out = NULL;
    if (!nicereply.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{40})\\b", &regex, error) != 0)
            return -1;
        nicereply.state = regex;
    }
    *out = &nicereply;
    return 0;
}
