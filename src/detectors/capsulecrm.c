/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/capsulecrm/capsulecrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_capsulecrm(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char value[72]; /* Bearer + SPACE + exactly 64 captured ASCII bytes + NUL. */
    int n = snprintf(value, sizeof(value), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(value)) return fail(error, "cannot format CapsuleCRM Authorization header");
    const br_header headers[] = {{"Authorization", value}};
    const br_http_request request = {.method = "GET", .url = "https://api.capsulecrm.com/api/v2/users",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 270};
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All Do errors are suppressed. ABI1 also mixes adapter allocation/setup
     * failures into this nonzero domain; never infer their stage from text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close-only until scan return without draining. ABI1 may
     * already have buffered the body and releases per request instead. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0; /* No verification-error setter, even for non-2xx or Do failures. */
}

static int scan_capsulecrm(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CapsuleCRM scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* With this fixed URL/method and ASCII keys, nil context is the known
         * constructor failure. Source skips the candidate, not the invocation. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Capture alphabet excludes whitespace: source TrimSpace is a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating CapsuleCRM result");
        else if (verify) rc = verify_capsulecrm(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending CapsuleCRM result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"capsulecrm"};
static br_detector capsulecrm = {
    .type = 270, .version = 0, .name = "CapsuleCRM", .custom_name = "",
    .description = "CapsuleCRM is a customer relationship management (CRM) platform. CapsuleCRM API keys can be used to access and manage customer data and interactions.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_capsulecrm,
};

int br_capsulecrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CapsuleCRM detector output");
    *out = NULL;
    if (br_key_pattern_init(&capsulecrm, "\\b([a-zA-Z0-9-._+=]{64})\\b", error) != 0) return -1;
    *out = &capsulecrm;
    return 0;
}
