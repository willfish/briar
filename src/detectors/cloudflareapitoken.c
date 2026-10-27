/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudflareapitoken/v1, v2 and common.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *account_id; } v2_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Only the actual common.go mechanics are shared. NULL account_id selects
 * VerifyUserToken; an exact 32-byte account ID selects VerifyAccountToken. */
static int verify_token(const br_scan_ctx *ctx, br_slice token, const char *account_id,
                         br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return fail(error, "cannot store CloudflareApiToken verification error");
        return 0;
    }
    static const char account_prefix[] = "https://api.cloudflare.com/client/v4/accounts/";
    static const char account_suffix[] = "/tokens/verify";
    char account_url[sizeof(account_prefix) + 32 + sizeof(account_suffix) - 1];
    const char *url = "https://api.cloudflare.com/client/v4/user/tokens/verify";
    if (account_id) {
        memcpy(account_url, account_prefix, sizeof(account_prefix) - 1);
        memcpy(account_url + sizeof(account_prefix) - 1, account_id, 32);
        memcpy(account_url + sizeof(account_prefix) - 1 + 32, account_suffix, sizeof(account_suffix));
        url = account_url;
    }
    char authorization[61] = "Bearer "; /* Complete max capture: 7+53+NUL. */
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 100,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error ? transport_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Copy/redact the COMPLETE CURRENT TOKEN, not the account ID, before any
     * cause owner is released. Core setter +1 is a fatal resource outcome. */
    int rc = br_result_set_verification_error(result, cause, &token, 1);
    /* Source verifier-defers drain/close and ignores body/read/drain/close
     * errors. ABI1 eager buffering/release and native client configuration
     * remain parity gaps, not a reason to inspect or parse the body here. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc != 0 ? fail(error, "cannot store CloudflareApiToken verification error") : 0;
}

static int scan_v1(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CloudflareApiToken v1 scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    int rc = br_captures_find(detector->state, input, &tokens, false, error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        /* Source TrimSpace changes nothing in this ASCII capture alphabet. */
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = fail(error, "cannot create CloudflareApiToken v1 result");
        if (rc == 0 && verify) rc = verify_token(ctx, token, NULL, &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append CloudflareApiToken v1 result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    return rc == 0 ? 0 : -1;
}

static int scan_v2(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CloudflareApiToken v2 scan");
    const v2_patterns *patterns = detector->state;
    if (!patterns->token || !patterns->account_id) return fail(error, "uninitialized CloudflareApiToken v2 patterns");
    size_t original_len = out->len;
    br_captures tokens = {0}, accounts = {0};
    int rc = br_captures_find(patterns->token, input, &tokens, false, error);
    if (rc == 0) rc = br_captures_find(patterns->account_id, input, &accounts, true, error);
    /* Only account IDs are unique. First-seen account order is one permitted
     * upstream map traversal; token occurrences and duplicates stay intact. */
    for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
        br_slice token = br_captures_at(&tokens, t);
        bool account_token = memcmp(token.data, "cfat_", 5) == 0;
        if (account_token && accounts.len) {
            for (size_t a = 0; rc == 0 && a < accounts.len; ++a) {
                br_result result = {0};
                if (br_finding_pair_bytes(&result, detector->type, token, "key",
                        br_captures_at(&accounts, a), "account_id", (br_slice){0}) != 0)
                    rc = fail(error, "cannot create CloudflareApiToken v2 account result");
                if (rc == 0 && verify) rc = verify_token(ctx, token, accounts.items[a], &result, error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = fail(error, "cannot append CloudflareApiToken v2 account result");
                br_result_clear(&result);
            }
        } else {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                rc = fail(error, "cannot create CloudflareApiToken v2 key result");
            /* cfat_ without IDs BYPASSES verification entirely, even for nil
             * context. cfut_ always uses the user endpoint regardless of IDs. */
            if (rc == 0 && verify && !account_token) rc = verify_token(ctx, token, NULL, &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append CloudflareApiToken v2 key result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&accounts);
    return rc == 0 ? 0 : -1;
}

static const char *const v1_keywords[] = {"cloudflare"};
static const char *const v2_keywords[] = {"cfut_", "cfat_"};
static br_detector v1 = {
    .type = 100, .version = 1, .name = "CloudflareApiToken", .custom_name = "",
    .description = "Cloudflare is a web infrastructure and website security company, providing content delivery network services, DDoS mitigation, Internet security, and distributed domain name server services. Cloudflare API tokens can be used to manage and interact with Cloudflare services.",
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_v1,
};
static v2_patterns patterns;
static const br_detector v2 = {
    .type = 100, .version = 2, .name = "CloudflareApiToken", .custom_name = "",
    .description = "Cloudflare is a web infrastructure and website security company. Cloudflare API tokens (cfut_/cfat_ prefixed, 2026+ format) can be used to manage and interact with Cloudflare services.",
    .keywords = v2_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_v2,
};

int br_cloudflareapitoken_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudflareApiToken v1 detector output");
    *out = NULL;
    if (br_key_pattern_init(&v1, "\\b([A-Za-z0-9_-]{40})\\b", error) != 0) return -1;
    *out = &v1;
    return 0;
}

int br_cloudflareapitoken_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudflareApiToken v2 detector output");
    *out = NULL;
    if (!patterns.token && br_regex_compile("\\b(cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8})\\b", &patterns.token, error) != 0)
        return -1;
    if (!patterns.account_id && br_regex_compile("\\b([a-f0-9]{32})\\b", &patterns.account_id, error) != 0)
        return -1;
    *out = &v2;
    return 0;
}
