/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/langfuse/langfuse.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *public_key;
    br_regex *secret_key;
} langfuse_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Redact the public key only. A NULL cause is passed through; it is a checked no-op. */
static int record_error(br_result *result, br_slice public_key, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, &public_key, 1) != 0)
        return fail(error, "cannot record Langfuse verification error");
    return 0;
}

static int verify_langfuse(const br_scan_ctx *ctx, br_slice public_key, br_slice secret,
                           br_result *result, char **error)
{
    /* Constructor failure is an unverified product, not a drop. Do not build
     * Basic auth, send, or release. */
    if (!ctx) return record_error(result, public_key, "net/http: nil Context", error);
    char *authorization = NULL;
    if (br_http_basic_auth(public_key, secret, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://cloud.langfuse.com/api/public/projects",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    /* Status is read before release clears it. The body and body_error are ignored. */
    int status = response.status;
    const char *cause = NULL;
    char status_cause[64];
    int rc = 0;
    /* Do failure is error presence, even when the transport cause pointer is NULL. */
    bool present = sent != 0;
    if (present) cause = send_error;
    /* Source builds this error before the deferred drain and close. A negative
     * return and a result that does not fit, including truncation, are fatal. */
    else if (status != 200 && status != 401) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = fail(error, "cannot format Langfuse verification status");
        else {
            present = true;
            cause = status_cause;
        }
    }
    br_http_release(ctx, &response);
    free(authorization);
    if (rc != 0) {
        free(send_error);
        return rc; /* No verdict and no setter. The scan rolls this invocation back. */
    }
    if (!present && status == 200) result->verified = true;
    if (present) rc = record_error(result, public_key, cause, error);
    free(send_error);
    return rc;
}

static int scan_langfuse(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Langfuse scan");
    const langfuse_patterns *patterns = detector->state;
    if (!patterns->public_key || !patterns->secret_key)
        return fail(error, "invalid or uninitialized Langfuse scan");
    size_t original_len = out->len;
    br_captures publics = {0}, secrets = {0};
    char *owned_error = NULL;
    /* Unique each side, then public-major, secret-minor. First-seen is the
     * chosen order. Either side empty yields no products. */
    int rc = br_captures_find(patterns->public_key, input, &publics, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret_key, input, &secrets, true, &owned_error);
    for (size_t p = 0; rc == 0 && p < publics.len; ++p) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            br_slice public_key = br_captures_at(&publics, p);
            br_slice secret = br_captures_at(&secrets, s);
            if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
                fail(&owned_error, "cannot create Langfuse finding");
                rc = -1;
            } else if (verify && verify_langfuse(ctx, public_key, secret, &result, &owned_error) != 0) {
                rc = -1;
            } else if (br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append Langfuse finding");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&publics);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const prefix_keywords[] = {"langfuse"};
static const char *const keywords[] = {"pk-lf-", "sk-lf-"};
static langfuse_patterns compiled;
static br_detector langfuse = {
    .type = 1021,
    .version = 0,
    .name = "Langfuse",
    .custom_name = "",
    .description = "Langfuse is a platform for building and scaling AI applications. Langfuse API keys can be used to access these services.",
    .keywords = keywords,
    .nkeywords = 2,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .state = &compiled,
    .scan = scan_langfuse,
};

int br_langfuse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Langfuse detector output");
    *out = NULL;
    if (!compiled.public_key &&
        br_regex_compile_prefixed(prefix_keywords, 1,
                                  "\\b(pk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                                  &compiled.public_key, error) != 0)
        return -1;
    if (!compiled.secret_key &&
        br_regex_compile_prefixed(prefix_keywords, 1,
                                  "\\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                                  &compiled.secret_key, error) != 0)
        return -1;
    *out = &langfuse;
    return 0;
}
