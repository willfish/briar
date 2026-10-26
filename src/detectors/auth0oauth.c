/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/auth0oauth/auth0oauth.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret, *domain; } auth0_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_auth0(const br_scan_ctx *ctx, const char *domain, const char *id,
                        const char *secret, br_result *result)
{
    const char prefix[] = "https://", suffix[] = "/oauth/token";
    const char head[] = "client_id=", middle[] = "&client_secret=";
    const char tail[] = "&code=AUTHORIZATION_CODE&grant_type=authorization_code&redirect_uri=undefined";
    size_t domain_len = strlen(domain), id_len = strlen(id), secret_len = strlen(secret);
    size_t url_fixed = sizeof(prefix) - 1 + sizeof(suffix);
    size_t form_fixed = sizeof(head) - 1 + sizeof(middle) - 1 + sizeof(tail);
    if (domain_len > SIZE_MAX - url_fixed || id_len > SIZE_MAX - form_fixed ||
        secret_len > SIZE_MAX - form_fixed - id_len) return -1;
    size_t form_size = form_fixed + id_len + secret_len;
    char *url = malloc(url_fixed + domain_len), *form = malloc(form_size);
    if (!url || !form) { free(url); free(form); return -1; }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain, domain_len);
    memcpy(url + sizeof(prefix) - 1 + domain_len, suffix, sizeof(suffix));
    /* url.Values.Encode sorts the keys. Every captured byte is form-unreserved. */
    size_t at = sizeof(head) - 1;
    memcpy(form, head, at);
    memcpy(form + at, id, id_len); at += id_len;
    memcpy(form + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(form + at, secret, secret_len); at += secret_len;
    memcpy(form + at, tail, sizeof(tail));
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)form, form_size - 1},
        .profile = BR_HTTP_DETECTOR_LOCAL, .detector_type = 55,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 404: break;
        case 403:
            if (response.body_error) cause = response.body_error;
            else result->verified = br_slice_find(response.body,
                    (br_slice){(const unsigned char *)"invalid_grant", sizeof("invalid_grant") - 1}, 0) != SIZE_MAX ||
                br_slice_find(response.body,
                    (br_slice){(const unsigned char *)"unauthorized_client", sizeof("unauthorized_client") - 1}, 0) != SIZE_MAX;
            break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = 0;
    if (cause) {
        /* Source supplies only the client ID, deliberately not secret or domain. */
        br_slice credential = {(const unsigned char *)id, id_len};
        rc = br_result_set_verification_error(result, cause, &credential, 1);
    }
    br_http_release(ctx, &response);
    free(error);
    free(form);
    free(url);
    return rc;
}

static int make_result(br_result *result, int32_t type, br_slice id, br_slice secret)
{
    if (br_finding_pair_bytes(result, type, secret, "client_secret", id, "client_id", (br_slice){0}) != 0)
        return -1;
    /* Raw is secret; RawV2 uses the opposite order, ID+secret, with no domain. */
    memcpy(result->raw_v2.data, id.data, id.len);
    memcpy(result->raw_v2.data + id.len, secret.data, secret.len);
    result->redacted = strdup((const char *)id.data);
    return result->redacted ? 0 : -1;
}

static int scan_auth0(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Auth0oauth scan arguments");
    const auth0_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->secret || !compiled->domain)
        return fail(error, "uninitialized Auth0oauth patterns");
    br_captures domains = {0}, ids = {0}, secrets = {0};
    int rc = br_captures_find(compiled->domain, input, &domains, true, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, true, error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, true, error);
    /* Preserve the full Cartesian product, including identical visible findings
     * for different domains. Go map order itself is unspecified. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            for (size_t d = 0; !rc && d < domains.len; ++d) {
                br_result result = {0};
                if (make_result(&result, detector->type, br_captures_at(&ids, i), br_captures_at(&secrets, s)) != 0 ||
                    (verify && verify_auth0(ctx, domains.items[d], ids.items[i], secrets.items[s], &result) != 0) ||
                    br_results_push(out, &result) != 0) {
                    br_result_clear(&result);
                    rc = fail(error, "out of memory creating Auth0oauth result");
                }
            }
        }
    }
    br_captures_clear(&secrets);
    br_captures_clear(&ids);
    br_captures_clear(&domains);
    return rc;
}

static auth0_patterns patterns;
static const char *const keywords[] = {"auth0"};
static const br_detector auth0 = {
    .type = 55, .version = 0, .name = "Auth0oauth", .custom_name = "",
    .description = "Auth0 is a service designed to handle authentication and authorization for users. "
                   "Oauth API keys can be used to impersonate applications and other things related to Auth0's API",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_auth0,
};

int br_auth0oauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Auth0oauth detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1,
            "\\b([a-zA-Z0-9_-]{32,60})\\b", &patterns.id, error) != 0) return -1;
    if (!patterns.secret && br_regex_compile("\\b([a-zA-Z0-9_-]{64,})\\b", &patterns.secret, error) != 0)
        return -1;
    if (!patterns.domain && br_regex_compile(
            "\\b([a-zA-Z0-9][a-zA-Z0-9._-]*auth0\\.com)\\b", &patterns.domain, error) != 0)
        return -1;
    *out = &auth0;
    return 0;
}
