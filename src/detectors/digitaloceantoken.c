/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/digitaloceantoken/digitaloceantoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int digitaloceantoken_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int digitaloceantoken_verify(const br_scan_ctx *ctx, const char *token,
                                    br_result *result, char **error)
{
    /* Source wraps constructor/Do errors with %w, but SetVerificationError
     * unwraps to the last typed cause. Do not add those discarded prefixes or
     * parse arbitrary injected leaf text. No secret arguments means no redaction. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return digitaloceantoken_fail(error, "cannot store DigitalOceanToken verification error");
        return 0;
    }
    /* Construction precedes auth preparation. Borrow the complete 71-byte
     * Bearer value and its NUL on the stack through synchronous send AND release. */
    char authorization[sizeof("Bearer ") + 64];
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, token, 65);
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.digitalocean.com/v2/account",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    /* The entire shared setup/allocation/Do domain is retained as an ordinary
     * finding error, without a stage classifier. Injected causes are leaf text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = digitaloceantoken_fail(error, "cannot format DigitalOceanToken status error");
            else cause = status_error;
            break;
        }
        }
    }
    /* Copy borrowed causes before release. Key echoes intentionally survive;
     * any nonzero setter return, including +1, is a fatal resource failure. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = digitaloceantoken_fail(error, "cannot store DigitalOceanToken verification error");
    /* Status ignores all body/read errors. Source verifier-defers Close only.
     * Eager ABI release, full private/native client, Go URL/Reader semantics,
     * and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int digitaloceantoken_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                  br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return digitaloceantoken_fail(error, "invalid or uninitialized DigitalOceanToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    /* Original byte-unique captures, without trimming or case normalization.
     * First-seen order is one permitted traversal of the source's token map. */
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&tokens, i), "key") != 0)
            rc = digitaloceantoken_fail(&owned_error, "cannot create DigitalOceanToken result");
        if (rc == 0 && verify)
            rc = digitaloceantoken_verify(ctx, tokens.items[i], &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = digitaloceantoken_fail(&owned_error, "cannot append DigitalOceanToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const digitaloceantoken_keywords[] = {"digitalocean"};
static br_detector digitaloceantoken_detector = {
    .type = 64, .version = 0, .name = "DigitalOceanToken", .custom_name = "",
    .description = "DigitalOcean is a cloud infrastructure provider offering cloud services to help deploy, manage, and scale applications. DigitalOcean tokens can be used to access and manage these services.",
    .keywords = digitaloceantoken_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = digitaloceantoken_scan,
};

int br_digitaloceantoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return digitaloceantoken_fail(error, "invalid DigitalOceanToken detector output");
    *out = NULL;
    /* Dispatch's digitalocean keyword is deliberately NOT the extraction list. */
    static const char *const prefixes[] = {"ocean", "do"};
    if (!digitaloceantoken_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(prefixes, 2, "\\b([A-Za-z0-9_-]{64})\\b", &pattern, error) != 0) return -1;
        digitaloceantoken_detector.state = pattern;
    }
    *out = &digitaloceantoken_detector;
    return 0;
}
