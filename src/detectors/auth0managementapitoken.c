/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/auth0managementapitoken/auth0managementapitoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *domain; } auth0_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_auth0(const br_scan_ctx *ctx, const char *token,
                         const char *domain, br_result *result)
{
    /* The captured domain is at most 16 + 1 + 3 + 10 bytes. */
    char url[sizeof("https:///api/v2/users") + 30];
    snprintf(url, sizeof(url), "https://%s/api/v2/users", domain);
    static const char bearer[] = "Bearer ";
    size_t token_len = strlen(token);
    if (token_len > SIZE_MAX - sizeof(bearer)) return -1;
    char *authorization = malloc(token_len + sizeof(bearer));
    if (!authorization) return -1;
    memcpy(authorization, bearer, sizeof(bearer) - 1);
    memcpy(authorization + sizeof(bearer) - 1, token, token_len + 1);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_LOCAL, .detector_type = 110,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* The source ignores the body and deferred drain/close errors. */
        switch (response.status) {
        case 200:
        case 403: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Redacted metadata is the domain, but verification errors redact only the token. */
    const br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc;
}

static int scan_auth0(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Auth0 Management API token scan arguments");
    const auth0_patterns *compiled = detector->state;
    if (!compiled->token || !compiled->domain)
        return fail(error, "uninitialized Auth0 Management API token detector");
    br_captures tokens = {0}, domains = {0};
    int rc = br_captures_find(compiled->token, input, &tokens, false, error);
    if (!rc) rc = br_captures_find(compiled->domain, input, &domains, false, error);
    /* Both alphabets exclude whitespace, so TrimSpace is a no-op. Gate whole
     * captures, then preserve every token-outer/domain-inner occurrence pair. */
    for (size_t t = 0; !rc && t < tokens.len; ++t) {
        br_slice token = br_captures_at(&tokens, t);
        if (token.len < 2000 || token.len > 5000) continue;
        for (size_t d = 0; !rc && d < domains.len; ++d) {
            br_result result = {0};
            int built = br_finding_pair(&result, detector->type, tokens.items[t], "token", domains.items[d], "domain");
            if (!built) {
                result.redacted = strdup(domains.items[d]);
                if (!result.redacted) built = -1;
            }
            if (built || (verify && verify_auth0(ctx, tokens.items[t], domains.items[d], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Auth0 Management API token result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&tokens);
    br_captures_clear(&domains);
    return rc;
}

static auth0_patterns patterns;
static const char *const keywords[] = {"auth0"};
static const br_detector auth0 = {
    .type = 110, .version = 0, .name = "Auth0ManagementApiToken", .custom_name = "",
    .description = "Auth0 provides authentication and authorization as a service. Auth0 Management "
                   "API tokens can be used to manage users, roles, permissions, and other aspects "
                   "of the Auth0 service.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = 5000, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_auth0,
};

int br_auth0managementapitoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Auth0 Management API token detector output");
    *out = NULL;
    if (!patterns.token &&
        br_regex_compile("\\b(ey[a-zA-Z0-9._-]+)\\b", &patterns.token, error) != 0)
        return -1;
    if (!patterns.domain &&
        br_regex_compile("([a-zA-Z0-9\\-]{2,16}\\.[a-zA-Z0-9_-]{2,3}\\.auth0\\.com)", &patterns.domain, error) != 0)
        return -1;
    *out = &auth0;
    return 0;
}
