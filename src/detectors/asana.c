/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/asanaoauth and
 * pkg/detectors/asanapersonalaccesstoken. */
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
static int verify_asana(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    static const char bearer[] = "Bearer ";
    size_t token_len = strlen(token);
    /* PAT numeric components and suffix are unbounded; do not truncate the header. */
    if (token_len > SIZE_MAX - sizeof(bearer)) return -1;
    char *auth = malloc(token_len + sizeof(bearer));
    if (!auth) return -1;
    memcpy(auth, bearer, sizeof(bearer) - 1);
    memcpy(auth + sizeof(bearer) - 1, token, token_len + 1);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.asana.com/api/1.0/users/me",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Status alone matters; upstream ignores body-drain and close errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
            cause = status_error;
            break;
        }
    }
    const br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_asana(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    /* FindAllStringSubmatch preserves repeated occurrences in both scanners. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_asana, error);
}

static const char *const keywords[] = {"asana"};
static br_detector oauth = {
    .type = 98, .version = 0, .name = "AsanaOauth", .custom_name = "",
    .description = "Asana is a work management platform that helps teams organize, track, and "
                   "manage their work. Asana OAuth tokens can be used to access and interact "
                   "with Asana's API on behalf of a user.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_asana,
};
static br_detector pat = {
    .type = 41, .version = 0, .name = "AsanaPersonalAccessToken", .custom_name = "",
    .description = "Asana is a web and mobile application designed to help teams organize, "
                   "track, and manage their work. Asana Personal Access Tokens can be used "
                   "to access and modify data within Asana.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_asana,
};

int br_asanaoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Asana OAuth detector output");
    *out = NULL;
    if (br_key_pattern_init(&oauth, "\\b([a-z/:0-9]{51})\\b", error) != 0) return -1;
    *out = &oauth;
    return 0;
}

int br_asanapersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Asana PAT detector output");
    *out = NULL;
    if (br_key_pattern_init(&pat, "\\b([0-9]{1,}/[0-9]{16,}(?:/[0-9]{16,})?:[A-Za-z0-9]{32,})\\b", error) != 0)
        return -1;
    *out = &pat;
    return 0;
}
