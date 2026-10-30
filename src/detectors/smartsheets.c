/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/smartsheets/smartsheets.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const smartsheets_keywords[] = {"smartsheet"};
static const char smartsheets_url[] = "https://api.smartsheet.com/2.0/sheets";

static int smartsheets_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int smartsheets_store(br_result *result, const char *cause, char **error)
{
    /* Source calls SetVerificationError with no secrets. */
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return smartsheets_fail(error, "cannot set Smartsheets verification error");
    return 0;
}

static int smartsheets_verify(const br_scan_ctx *ctx, const char *key, size_t key_len,
                              br_result *result, char **error)
{
    char authorization[48];
    if (key_len > sizeof(authorization) - 8)
        return smartsheets_fail(error, "invalid Smartsheets capture");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, key_len);
    authorization[7 + key_len] = '\0';
    /* Fixed URL. A nil context is a verification error, not a constructor skip. */
    if (!ctx) return smartsheets_store(result, "net/http: nil Context", error);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = smartsheets_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    if (send_rc != 0) {
        int stored = smartsheets_store(result, transport_error, error);
        free(transport_error);
        br_http_release(ctx, &response);
        return stored;
    }
    free(transport_error);
    if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        br_http_release(ctx, &response);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            return smartsheets_fail(error, "cannot format Smartsheets status");
        return smartsheets_store(result, status_error, error);
    }
    br_http_release(ctx, &response);
    return 0;
}

static int smartsheets_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return smartsheets_fail(error, "invalid or uninitialized Smartsheets scan");
    size_t original_len = out->len;
    br_captures found = {0}, keys = {0};
    char *owned_error = NULL;
    /* Dispatch keyword is smartsheet; extraction prefix is sheet. Unique, first seen. */
    int rc = br_captures_find(detector->state, input, &found, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < found.len; ++i)
        if (br_captures_push(&keys, br_captures_at(&found, i), true, &owned_error) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 26 && key.len != 37)
            rc = smartsheets_fail(&owned_error, "invalid Smartsheets capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = smartsheets_fail(&owned_error, "cannot create Smartsheets result");
        else if (verify)
            rc = smartsheets_verify(ctx, keys.items[i], key.len, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = smartsheets_fail(&owned_error, "cannot append Smartsheets result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&found);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector smartsheets_detector = {
    .type = 247, .version = 0, .name = "Smartsheets", .custom_name = "",
    .description = "Smartsheets is a platform for work management and automation. Smartsheets API keys can be used to access and modify data and automate workflows within the platform.",
    .keywords = smartsheets_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = smartsheets_scan,
};

int br_smartsheets_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"sheet"};
    if (error) *error = NULL;
    if (!out) return smartsheets_fail(error, "invalid Smartsheets detector output");
    *out = NULL;
    if (!smartsheets_detector.state &&
        br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9]{26}|[a-zA-Z0-9]{37})\\b",
                                  (br_regex **)&smartsheets_detector.state, error) != 0)
        return -1;
    *out = &smartsheets_detector;
    return 0;
}
