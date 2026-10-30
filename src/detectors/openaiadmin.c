/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/openaiadmin/openaiadmin.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char openaiadmin_url[] = "https://api.openai.com/v1/organization/admin_api_keys";

static int openaiadmin_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int openaiadmin_redact(br_result *result, br_slice key)
{
    /* token[:11] + "..." + token[len-4:]. The grammar fixes the length at 133. */
    if (key.len < 15) return -1;
    result->redacted = malloc(11 + 3 + 4 + 1);
    if (!result->redacted) return -1;
    memcpy(result->redacted, key.data, 11);
    memcpy(result->redacted + 11, "...", 3);
    memcpy(result->redacted + 14, key.data + key.len - 4, 4);
    result->redacted[18] = '\0';
    return 0;
}

static int openaiadmin_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* NewRequestWithContext fails before either Header.Set. A nil context is a
     * retained verification error, not a dropped candidate and not a send. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1)
            ? openaiadmin_fail(error, "cannot set OpenAIAdmin verification error") : 0;
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) return openaiadmin_fail(error, "cannot allocate OpenAIAdmin authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = openaiadmin_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = openaiadmin_fail(error, "cannot format OpenAIAdmin status");
        else cause = status_error;
    }
    /* Body drain and close errors are ignored. NULL cause is a setter no-op.
     * The token is redacted from the copied cause before release. */
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = openaiadmin_fail(error, "cannot set OpenAIAdmin verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc;
}

static int openaiadmin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return openaiadmin_fail(error, "invalid or uninitialized OpenAIAdmin scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Map assignment keeps one copy of each token. First-seen order is the
     * deterministic stand-in for Go's random map iteration. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = openaiadmin_fail(&owned_error, "cannot create OpenAIAdmin result");
        else if (openaiadmin_redact(&result, key) != 0)
            rc = openaiadmin_fail(&owned_error, "cannot redact OpenAIAdmin result");
        else if (verify && openaiadmin_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = openaiadmin_fail(&owned_error, "cannot append OpenAIAdmin result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const openaiadmin_keywords[] = {"sk-admin-"};
static br_detector openaiadmin_detector = {
    .type = 1040, .version = 0, .name = "OpenAIAdmin", .custom_name = "",
    .description = "OpenAI Admin API keys provide administrative access to OpenAI organization resources. These keys can be used to manage API keys, audit logs, and other organization-level settings.",
    .keywords = openaiadmin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = openaiadmin_scan,
};

int br_openaiadmin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return openaiadmin_fail(error, "invalid OpenAIAdmin detector output");
    *out = NULL;
    if (!openaiadmin_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58})\\b",
                             &regex, error) != 0)
            return -1;
        openaiadmin_detector.state = regex;
    }
    *out = &openaiadmin_detector;
    return 0;
}
