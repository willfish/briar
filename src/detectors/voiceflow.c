/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/voiceflow/voiceflow.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { VF_ABORT = -1, VF_KEEP = 0, VF_SKIP = 1 } vf_outcome;

static int vf_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int vf_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return vf_fail(error, "cannot set Voiceflow verification error");
    return 0;
}

static char *vf_status_error(int status, br_slice body, char **error)
{
    /* Go copies the whole body. A NUL cannot live in the C error string; that
     * diagnostic is unsupported rather than silently truncated. */
    if (body.len && memchr(body.data, 0, body.len)) {
        vf_fail(error, "unsupported: Voiceflow NUL response body diagnostic");
        return NULL;
    }
    char prefix[80];
    int n = snprintf(prefix, sizeof(prefix), "unexpected HTTP response [status=%d, body=", status);
    if (n < 0 || (size_t)n >= sizeof(prefix)) {
        vf_fail(error, "cannot format Voiceflow status");
        return NULL;
    }
    if (body.len > SIZE_MAX - (size_t)n - 2) {
        vf_fail(error, "Voiceflow response diagnostic too large");
        return NULL;
    }
    char *text = malloc((size_t)n + body.len + 2);
    if (!text) {
        vf_fail(error, "cannot allocate Voiceflow status");
        return NULL;
    }
    memcpy(text, prefix, (size_t)n);
    if (body.len) memcpy(text + n, body.data, body.len);
    text[n + body.len] = ']';
    text[n + body.len + 1] = '\0';
    return text;
}

static vf_outcome vf_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const unsigned char payload[] = "{\"question\": \"why is the sky blue?\"}";
    char authorization[128];
    if (key.len >= sizeof(authorization)) {
        vf_fail(error, "cannot format Voiceflow authorization");
        return VF_ABORT;
    }
    memcpy(authorization, key.data, key.len);
    authorization[key.len] = '\0';
    /* Payload exists before the nil-context continue. Header.Set uses the raw key. */
    if (!ctx) return VF_SKIP;
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://general-runtime.voiceflow.com/knowledge-base/query",
        .headers = headers, .nheaders = 3, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char *owned = NULL;
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        br_slice body = response.body_error ? (br_slice){0} : response.body;
        owned = vf_status_error(response.status, body, error);
        if (!owned) rc = -1;
        else cause = owned;
    }
    if (rc == 0) rc = vf_cause(result, cause, key, error);
    br_http_release(ctx, &response);
    free(transport_error);
    free(owned);
    return rc == 0 ? VF_KEEP : VF_ABORT;
}

static int vf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return vf_fail(error, "invalid or uninitialized Voiceflow scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        vf_outcome outcome = VF_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            vf_fail(&owned_error, "cannot create Voiceflow result");
            outcome = VF_ABORT;
        } else if (verify)
            outcome = vf_verify(ctx, key, &result, &owned_error);
        if (outcome == VF_ABORT) rc = -1;
        else if (outcome == VF_KEEP && br_results_push(out, &result) != 0) {
            vf_fail(&owned_error, "cannot append Voiceflow result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const vf_keywords[] = {"vf", "dm"};
static br_regex *vf_regex;
static br_detector vf_detector = {
    .type = 937, .version = 0, .name = "Voiceflow", .custom_name = "",
    .description = "Voiceflow is an AI service designed to transact with customers. "
                   "API keys may be used to access customer data.",
    .keywords = vf_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = vf_scan,
};

int br_voiceflow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return vf_fail(error, "invalid Voiceflow detector output");
    *out = NULL;
    /* Keywords are engine dispatch only. The pattern is unprefixed and case-sensitive. */
    if (!vf_regex && br_regex_compile(
            "\\b(VF\\.(?:(?:DM|WS)\\.)?[a-fA-F0-9]{24}\\.[a-zA-Z0-9]{16})\\b",
            &vf_regex, error) != 0)
        return -1;
    vf_detector.state = vf_regex;
    *out = &vf_detector;
    return 0;
}
