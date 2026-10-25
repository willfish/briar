/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/airtableoauth and
 * pkg/detectors/airtablepersonalaccesstoken. */
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

/* Both upstream verifyMatch implementations are identical. */
static int verify_airtable(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    static const char bearer[] = "Bearer ";
    size_t token_len = strlen(token);
    if (token_len > SIZE_MAX - sizeof(bearer)) return -1;
    char *auth = malloc(token_len + sizeof(bearer));
    if (!auth) return -1;
    memcpy(auth, bearer, sizeof(bearer) - 1);
    memcpy(auth + sizeof(bearer) - 1, token, token_len + 1);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.airtable.com/v0/meta/whoami",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores body-drain/close errors and always returns nil ExtraData. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(auth);
    return rc;
}

static int scan_airtable(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "token", verify_airtable, error);
}

static const char *const keywords[] = {"airtable"};
/* The PAT description intentionally retains upstream's OAuth wording. */
static const char description[] =
    "Airtable is a cloud collaboration service that offers database-like features. "
    "Airtable OAuth tokens can be used to access and modify data within Airtable bases.";

static br_detector oauth = {
    .type = 1014, .version = 0, .name = "AirtableOAuth", .custom_name = "",
    .description = description, .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_airtable,
};
static br_detector pat = {
    .type = 1015, .version = 0, .name = "AirtablePersonalAccessToken", .custom_name = "",
    .description = description, .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_airtable,
};

int br_airtableoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Airtable OAuth detector output");
    *out = NULL;
    if (!oauth.state) {
        br_regex *regex = NULL;
        /* The keyword is an engine prefilter only; direct scanning needs no prefix. */
        if (br_regex_compile("\\b([[:alnum:]]+\\.v1\\.[a-zA-Z0-9_-]+\\.[a-f0-9]+)\\b",
                             &regex, error) != 0)
            return -1;
        oauth.state = regex;
    }
    *out = &oauth;
    return 0;
}

int br_airtablepersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Airtable PAT detector output");
    *out = NULL;
    if (!pat.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b",
                                      &regex, error) != 0)
            return -1;
        pat.state = regex;
    }
    *out = &pat;
    return 0;
}
