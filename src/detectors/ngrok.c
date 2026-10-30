/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ngrok/ngrok.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Go map iteration order is unspecified. This scan emits first-seen order. */
#ifndef NGROK_BEFORE_RELEASE
#define NGROK_BEFORE_RELEASE(result) ((void)(result))
#endif

static const char *const ngrok_keywords[] = {"ngrok"};
static const char ngrok_url[] = "https://api.ngrok.com/agent_ingresses";
static const char ngrok_marker[] = "ERR_NGROK_206";
static const char ngrok_capture[] = "\\b(2[a-zA-Z0-9]{26}_\\d[a-zA-Z0-9]{20})\\b";

static int ngrok_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int ngrok_status(char *out, size_t cap, int status)
{
    int n = snprintf(out, cap, "ngrok: unexpected status code: %d", status);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

static int ngrok_commit(br_result *result, bool verified, const char *cause, br_slice token, char **error)
{
    result->verified = verified;
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return ngrok_fail(error, "cannot record Ngrok verification error");
    return 0;
}

static int ngrok_verify(const br_detector *detector, const br_scan_ctx *ctx, br_slice token,
                        br_result *result, char **error)
{
    /* NewRequestWithContext rejects a nil context before Do. Retain the finding. */
    if (!ctx) return ngrok_commit(result, false, "net/http: nil Context", token, error);
    if (token.len != 49) return ngrok_fail(error, "invalid Ngrok token");
    char authorization[57];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[56] = '\0';
    /* Header.Set canonicalizes ngrok-version to Ngrok-Version. Briar does not. */
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Ngrok-Version", "2"},
    };
    const br_http_request request = {
        .method = "GET", .url = ngrok_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 0, .detector_type = detector->type,
    };
    br_http_response response = {0};
    char status_error[64];
    char *send_error = NULL, *owned_cause = NULL;
    const char *cause = NULL;
    bool verified = false;
    const br_slice marker = {(const unsigned char *)ngrok_marker, sizeof(ngrok_marker) - 1};
    int rc = br_http_send(ctx, &request, &response, &send_error);
    if (rc != 0) {
        /* A NULL Do cause stays NULL. Do not invent a diagnostic. */
        cause = send_error;
        rc = 0;
    } else if (response.status == 200) {
        verified = true;
    } else if (response.status == 401 || response.status == 403) {
        verified = false;
    } else if (response.status == 400 && response.body_error) {
        /* ReadAll wins before the marker, even when the partial body contains it. */
        owned_cause = strdup(response.body_error);
        if (!owned_cause) rc = ngrok_fail(error, "cannot copy Ngrok read error");
        else cause = owned_cause;
    } else if (response.status == 400 && !response.body.data && response.body.len) {
        /* Reached only after the read-error branch. Empty {NULL,0} stays valid. */
        rc = ngrok_fail(error, "invalid Ngrok response body");
    } else if (response.status == 400 && br_slice_find(response.body, marker, 0) != SIZE_MAX) {
        verified = true;
    } else if (ngrok_status(status_error, sizeof(status_error), response.status) != 0) {
        rc = ngrok_fail(error, "cannot format Ngrok status");
    } else {
        cause = status_error;
    }
    /* Branch and owned cause are fixed. Headers, URL, and token stay alive. */
    NGROK_BEFORE_RELEASE(result);
    br_http_release(ctx, &response);
    if (rc == 0) rc = ngrok_commit(result, verified, cause, token, error);
    free(send_error);
    free(owned_cause);
    return rc;
}

static int ngrok_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ngrok_fail(error, "invalid or uninitialized Ngrok scan");
    size_t original_len = out->len;
    br_captures matches = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find((const br_regex *)detector->state, input, &matches, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < matches.len; ++i) {
        br_slice key = br_captures_at(&matches, i);
        /* Drop before uniqueness, including NoV. Equality 3 remains. ASCII only. */
        if (br_ascii_shannon_entropy(key) < 3) continue;
        if (br_captures_push(&keys, key, true, &owned_error) != 0) rc = -1;
    }
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ngrok_fail(&owned_error, "cannot create Ngrok result");
        else if (verify && ngrok_verify(detector, ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = ngrok_fail(&owned_error, "cannot append Ngrok result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&matches);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector ngrok_detector = {
    .type = 966, .version = 0, .name = "Ngrok", .custom_name = "",
    .description = "Ngrok is a service that provides secure introspectable tunnels to localhost. Ngrok keys can be used to manage and control these tunnels.",
    .keywords = ngrok_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ngrok_scan,
};

int br_ngrok_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ngrok_fail(error, "invalid Ngrok detector output");
    *out = NULL;
    if (!ngrok_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(ngrok_keywords, 1, ngrok_capture, &regex, error) != 0) return -1;
        ngrok_detector.state = regex;
    }
    *out = &ngrok_detector;
    return 0;
}
