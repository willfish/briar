/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/assemblyai/assemblyai.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_assemblyai(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.assemblyai.com/v2/transcript",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 389,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors from its deferred body drain and close. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_assemblyai(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_assemblyai, error);
}

static const char *const keywords[] = {"assemblyai"};
static br_detector assemblyai = {
    .type = 389, .version = 0, .name = "AssemblyAI", .custom_name = "",
    .description = "AssemblyAI is a service that provides speech-to-text transcription. "
                   "AssemblyAI keys can be used to access and utilize the transcription services provided by AssemblyAI.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_assemblyai,
};

int br_assemblyai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AssemblyAI detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&assemblyai, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &assemblyai;
    return 0;
}
