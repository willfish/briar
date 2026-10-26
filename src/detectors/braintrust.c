/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/braintrust/braintrust.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_braintrust(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0 ? -1 : 0;
    char authorization[59]; /* Bearer + SPACE + 51 captured ASCII bytes + NUL. */
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = "https://api.braintrust.dev/v1/project?limit=1",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 1053};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200 || response.status == 403) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* Status-only verification ignores all body/read/drain errors. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0; /* Core setter allocation failures can be positive. */
}

static int scan_braintrust(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Braintrust scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    int rc = br_captures_find(detector->state, input, &tokens, true, error);
    /* One deterministic source-map order. Projection is unconditional: NoV,
     * verified and error findings all own the same eight-byte-prefix display. */
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&tokens, i), "token") != 0)
            rc = fail(error, "out of memory creating Braintrust result");
        else {
            result.redacted = malloc(12);
            if (!result.redacted) rc = fail(error, "out of memory projecting Braintrust token");
            else {
                memcpy(result.redacted, tokens.items[i], 8);
                memcpy(result.redacted + 8, "...", 4); /* Includes owned NUL terminator. */
                if (verify && verify_braintrust(ctx, tokens.items[i], &result) != 0)
                    rc = fail(error, "out of memory recording Braintrust verification error");
            }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Braintrust result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"braintrust"};
/* Registration and feature-gating are engine policy, not scan/init conditions. */
static br_detector braintrust = {
    .type = 1053, .version = 0, .name = "BrainTrustApiKey", .custom_name = "",
    .description = "Braintrust is an AI evaluation and observability platform. Braintrust API keys can be used to access evaluation, observability, and AI development resources within the Braintrust platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_braintrust,
};

int br_braintrust_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Braintrust detector output");
    *out = NULL;
    if (!braintrust.state) {
        br_regex *pattern = NULL;
        /* DIRECT pattern; dispatch keyword must not become an extraction prefix. */
        if (br_regex_compile("\\b(sk-[A-Za-z0-9]{48})\\b", &pattern, error) != 0) return -1;
        braintrust.state = pattern;
    }
    *out = &braintrust;
    return 0;
}
