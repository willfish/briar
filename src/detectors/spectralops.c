/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/spectralops/spectralops.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int spectral_verify(const br_scan_ctx *ctx, br_result *result, br_slice token)
{
    const char *cause = NULL;
    char status_error[64];
    char authorization[64];
    if (token.len != 36) return fail(NULL, "invalid SpectralOps token");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, 36);
    authorization[43] = '\0';
    /* NewRequestWithContext precedes Header.Set. A nil context is a verification error. */
    if (!ctx) cause = "net/http: nil Context";
    else {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://get.spectralops.io/api/v1/users",
            .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error; /* NULL diagnostic stays NULL. */
        } else if (response.status == 200) {
            result->verified = true;
        } else if (response.status != 401 && response.status != 403) {
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
        }
        int rc = br_result_set_verification_error(result, cause, &token, 1);
        br_http_release(ctx, &response);
        free(send_error);
        return rc == 0 ? 0 : -1;
    }
    return br_result_set_verification_error(result, cause, &token, 1) == 0 ? 0 : -1;
}

static int scan_spectral(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SpectralOps scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    /* Source ranges a uniqueness map. First-seen order is one permitted traversal. */
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "token") != 0)
            rc = fail(&owned_error, "cannot create SpectralOps result");
        if (!rc && verify && spectral_verify(ctx, &result, token) != 0)
            rc = fail(&owned_error, "cannot verify SpectralOps token");
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append SpectralOps result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static br_regex *pattern;
static const char *const keywords[] = {"spu-"};
static br_detector spectral = {
    .type = 1051, .version = 0, .name = "SpectralOps", .custom_name = "",
    .description = "SpectralOps is a DevSecOps platform for detecting secrets and misconfigurations. Spectral personal API tokens can be used to access and interact with Spectral services and resources.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_spectral,
};

int br_spectralops_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SpectralOps detector output");
    *out = NULL;
    if (!pattern && br_regex_compile("\\b(spu-[a-z0-9]{32})\\b", &pattern, error) != 0) return -1;
    spectral.state = pattern;
    *out = &spectral;
    return 0;
}
