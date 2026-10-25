/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/amplitudeapikey/amplitudeapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_amplitudeapikey(const br_scan_ctx *ctx, br_slice key,
                                  br_slice secret, br_result *result)
{
    char *auth = NULL;
    if (br_http_basic_auth(key, secret, &auth, NULL) != 0) return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://amplitude.com/api/2/taxonomy/category",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 42,
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
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies neither key nor secret to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    free(auth);
    return rc;
}

static int scan_amplitudeapikey(const br_detector *detector, const br_scan_ctx *ctx,
                                bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AmplitudeApiKey scan arguments");

    /* keyPat and secretPat are identical upstream. This unique collection is
     * both sets, so matching indices mean key == secret and must be skipped. */
    br_captures tokens = {0};
    int rc = br_captures_find(detector->state, input, &tokens, true, error);
    for (size_t k = 0; !rc && k < tokens.len; ++k) {
        br_slice key = br_captures_at(&tokens, k);
        for (size_t s = 0; !rc && s < tokens.len; ++s) {
            if (k == s) continue;
            br_slice secret = br_captures_at(&tokens, s);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret",
                                      (br_slice){0}) != 0 ||
                (verify && verify_amplitudeapikey(ctx, key, secret, &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating AmplitudeApiKey result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&tokens);
    return rc;
}

static const char *const keywords[] = {"amplitude"};
static br_detector amplitudeapikey = {
    .type = 42, .version = 0, .name = "AmplitudeApiKey", .custom_name = "",
    .description = "Amplitude is a product analytics service that helps companies track and analyze user behavior within web and mobile applications. Amplitude API keys can be used to access and modify this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_amplitudeapikey,
};

int br_amplitudeapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AmplitudeApiKey detector output");
    *out = NULL;
    if (!amplitudeapikey.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{32})\\b", &regex, error) != 0)
            return -1;
        amplitudeapikey.state = regex;
    }
    *out = &amplitudeapikey;
    return 0;
}
