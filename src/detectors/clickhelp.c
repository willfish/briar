/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clickhelp/clickhelp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *portal, *email, *key; } clickhelp_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    /* Source passes ZERO redaction arguments: preserve portal, email, API key
     * and Basic echoes. The setter's positive 1 is a fatal resource failure. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_clickhelp(const br_scan_ctx *ctx, const char *portal, br_slice email,
                             br_slice key, br_result *result)
{
    /* Source constructs the request BEFORE SetBasicAuth. Its known nil-context
     * failure is retained, but must not allocate a Basic value first. */
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char url[96]; /* Portal capture <=37 ASCII bytes; fixed scheme/path. */
    snprintf(url, sizeof(url), "https://%s/api/v1/projects", portal);
    char *authorization = NULL;
    if (br_http_basic_auth(email, key, &authorization, NULL)) { free(authorization); return -1; }
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error ? transport_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Copy causes before releasing response-owned storage. Body/read/drain/
     * close errors are ignored; eager ABI1 buffering/release does not establish
     * source verifier-deferred drain/close timing or native diagnostic parity. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return rc ? -1 : 0;
}

static int scan_clickhelp(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid ClickHelp scan");
    const clickhelp_patterns *compiled = detector->state;
    if (!compiled->portal || !compiled->email || !compiled->key) return fail(error, "uninitialized ClickHelp patterns");
    br_captures portals = {0}, emails = {0}, keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->portal, input, &portals, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->email, input, &emails, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, &owned_error);
    /* All three independent sets are byte-unique and case-preserving. Keep
     * portal-major/email-middle/key-inner products, with no success break. */
    for (size_t p = 0; !rc && p < portals.len; ++p) {
        for (size_t e = 0; !rc && e < emails.len; ++e) {
            for (size_t k = 0; !rc && k < keys.len; ++k) {
                br_result result = {0};
                br_slice portal = br_captures_at(&portals, p), email = br_captures_at(&emails, e), key = br_captures_at(&keys, k);
                /* API key is REQUIRED but absent from Raw/RawV2/parts. Multiple
                 * keys deliberately produce identical NoV projections. */
                if (br_finding_pair_bytes(&result, detector->type, portal, "url", email, "email", (br_slice){0}))
                    rc = fail(&owned_error, "cannot create ClickHelp result");
                if (!rc && verify) {
                    if (verify_clickhelp(ctx, portals.items[p], email, key, &result))
                        rc = fail(&owned_error, "cannot verify ClickHelp candidate");
                    else {
                        /* Source sets primary AFTER SetVerificationError, for
                         * EVERY retained verified-mode result: 200, 401, nil
                         * context or other errors. NoV remains portal-located.
                         * Own the bytes; direct-scan line/offset stay unset. */
                        result.primary_secret.data = malloc(key.len);
                        if (!result.primary_secret.data) rc = fail(&owned_error, "cannot copy ClickHelp primary secret");
                        else { memcpy(result.primary_secret.data, key.data, key.len); result.primary_secret.len = key.len; }
                    }
                }
                if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append ClickHelp result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&portals); br_captures_clear(&emails); br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static clickhelp_patterns patterns;
static const char *const dispatch_keywords[] = {"clickhelp.co"};
static const char *const key_prefixes[] = {"clickhelp", "key", "token", "api", "secret"};
static const br_detector clickhelp = {
    .type = 456, .version = 0, .name = "ClickHelp", .custom_name = "",
    .description = "ClickHelp is a documentation tool that allows users to create and manage online documentation. ClickHelp API keys can be used to access and modify documentation data.",
    .keywords = dispatch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_clickhelp,
};

int br_clickhelp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ClickHelp detector output");
    *out = NULL;
    if (!patterns.portal && br_regex_compile("\\b([0-9A-Za-z-]{3,20}\\.(?:try\\.)?clickhelp\\.co)\\b", &patterns.portal, error)) return -1;
    if (!patterns.email && br_regex_compile(br_email_pattern, &patterns.email, error)) return -1;
    if (!patterns.key && br_regex_compile_prefixed(key_prefixes, 5, "\\b([0-9A-Za-z]{24})\\b", &patterns.key, error)) return -1;
    *out = &clickhelp;
    return 0;
}
