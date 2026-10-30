/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/phraseaccesstoken/phraseaccesstoken.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_phrase(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    char authorization[72];
    char status_error[64];
    br_slice secret = {(const unsigned char *)token, strlen(token)};
    int n = snprintf(authorization, sizeof(authorization), "token %s", token);
    if (n != 70 || secret.len != 64) return -1;
    /* Fixed URL is complete before NewRequestWithContext rejects a nil context. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.phrase.com/v2/projects",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 1037,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else {
        /* io.Copy drain errors are ignored; status is still decisive. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_phrase(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_phrase, error);
}

static const char *const keywords[] = {"phrase"};
static br_detector phrase = {
    .type = 1037, .version = 0, .name = "PhraseAccessToken", .custom_name = "",
    .description = "Phrase is a translation management platform for software projects. Phrase API "
                   "keys can be used to access translation projects, locales, and manage translations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_phrase,
};

int br_phraseaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid PhraseAccessToken detector output");
    *out = NULL;
    if (!phrase.state) {
        static const char *const prefixes[] = {"phrase", "accessToken", "access_token"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 3, "\\b([a-z0-9]{64})\\b", &compiled, error) != 0)
            return -1;
        phrase.state = compiled;
    }
    *out = &phrase;
    return 0;
}
