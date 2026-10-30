/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tly/tly.go.
 * Unique keys keep first-seen order; Go map iteration is unstable. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_tly(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_slice redact = {(const unsigned char *)key, strlen(key)};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &redact, 1) == 0
            ? 0 : fail(error, "cannot set TLy verification error");
    char authorization[96];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return fail(error, "cannot format TLy authorization");
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.t.ly/api/v1/link/list",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    const char *cause = NULL;
    char message[64];
    int rc = 0;
    if (sent) cause = transport_error;
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        cause = message;
    }
    if (br_result_set_verification_error(result, cause, &redact, 1) != 0)
        rc = fail(error, "cannot set TLy verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_tly(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TLy scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create TLy result");
            outcome = -1;
        } else if (verify && verify_tly(ctx, keys.items[i], &result, &owned_error) != 0)
            outcome = -1;
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append TLy result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"tly"};
static br_detector tly = {
    .type = 586, .version = 0, .name = "TLy", .custom_name = "",
    .description = "TLy is a URL shortening service. TLy API keys can be used to access and manage shortened URLs.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_tly,
};

int br_tly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TLy detector output");
    *out = NULL;
    if (!tly.state && br_key_pattern_init(&tly, "\\b([0-9A-Za-z]{60})\\b", error) != 0) return -1;
    *out = &tly;
    return 0;
}
