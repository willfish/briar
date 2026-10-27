/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudflareglobalapikey/{v1,v2,common.go}. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *email_pattern;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_global_key(const br_scan_ctx *ctx, const char *key, const char *email,
                              br_result *result, char **error)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot store CloudflareGlobalApiKey verification error");
        return 0;
    }
    /* Borrow complete captures. Email length is unbounded by the source, and
     * quoted controls are neither filtered, normalized nor copied to a cap. */
    const br_header headers[] = {{"X-Auth-Email", email}, {"X-Auth-Key", key}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloudflare.com/client/v4/user",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .detector_type = 58,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
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
    /* Key-only redaction intentionally leaves emails in causes. Copy before
     * release; setter +1 is resource failure, never a candidate outcome. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    /* Source verifier-defers drain/close and ignores body/read/drain/close
     * errors. ABI1 eager buffering/release and full client configuration remain
     * partial. Generic header rejection wording can differ from Go's cause. */
    return rc != 0 ? fail(error, "cannot store CloudflareGlobalApiKey verification error") : 0;
}

static int scan_global_keys(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !email_pattern || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CloudflareGlobalApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(email_pattern, input, &emails, true, error);
    /* Capture 1, original bytes/case, independently unique emails. Source
     * TrimSpace is a no-op at these grammars' edges, not inside quoted emails.
     * First-seen email order is one permitted upstream map traversal. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        if (detector->version == 2 && emails.len == 0) {
            /* Visible v2-only exception: report key-only and bypass ALL
             * verification, including nil-context error creation. V1 emits none. */
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(error, "cannot create CloudflareGlobalApiKey unpaired result");
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append CloudflareGlobalApiKey unpaired result");
            br_result_clear(&result);
            continue;
        }
        for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key, "key",
                    br_captures_at(&emails, e), "email", (br_slice){0}) != 0)
                rc = fail(error, "cannot create CloudflareGlobalApiKey paired result");
            if (rc == 0) {
                result.redacted = strdup(emails.items[e]);
                if (!result.redacted) rc = fail(error, "cannot copy CloudflareGlobalApiKey Redacted email");
            }
            if (rc == 0 && verify) rc = verify_global_key(ctx, keys.items[k], emails.items[e], &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append CloudflareGlobalApiKey paired result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&emails);
    return rc == 0 ? 0 : -1;
}

static const char *const v1_keywords[] = {"cloudflare"};
static const char *const v2_keywords[] = {"cfk_"};
static br_detector v1 = {
    .type = 58, .version = 1, .name = "CloudflareGlobalApiKey", .custom_name = "",
    .description = "Cloudflare is a web infrastructure and website security company. Its services include content delivery network (CDN), DDoS mitigation, Internet security, and distributed domain name server (DNS) services. Cloudflare API keys can be used to access and modify these services.",
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_global_keys,
};
static br_detector v2 = {
    .type = 58, .version = 2, .name = "CloudflareGlobalApiKey", .custom_name = "",
    .description = "Cloudflare is a web infrastructure and website security company. Cloudflare API keys (cfk_ prefixed, 2026+ format) can be used to access and modify these services.",
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_global_keys,
};

int br_cloudflareglobalapikey_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudflareGlobalApiKey v1 detector output");
    *out = NULL;
    if (!email_pattern && br_regex_compile(br_email_pattern, &email_pattern, error) != 0) return -1;
    if (br_key_pattern_init(&v1, "\\b([a-f0-9]{37,45})\\b", error) != 0) return -1;
    *out = &v1;
    return 0;
}

int br_cloudflareglobalapikey_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudflareGlobalApiKey v2 detector output");
    *out = NULL;
    if (!email_pattern && br_regex_compile(br_email_pattern, &email_pattern, error) != 0) return -1;
    if (!v2.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(cfk_[a-zA-Z0-9]{40}[a-f0-9]{8})\\b", &pattern, error) != 0) return -1;
        v2.state = pattern;
    }
    *out = &v2;
    return 0;
}
