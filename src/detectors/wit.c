/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/wit/wit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char wit_url[] = "https://api.wit.ai/apps?offset=1&limit=2";

static int wit_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int wit_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (key.len != 32) return wit_fail(error, "invalid Wit capture");
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1)
            ? wit_fail(error, "cannot set Wit verification error") : 0;
    char authorization[7 + 32 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 32);
    authorization[39] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = wit_url, .headers = headers, .nheaders = 1,
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
    else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = wit_fail(error, "cannot format Wit status");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = wit_fail(error, "cannot set Wit verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int wit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return wit_fail(error, "invalid or uninitialized Wit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = wit_fail(&owned_error, "cannot create Wit result");
        else if (verify && wit_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = wit_fail(&owned_error, "cannot append Wit result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const wit_keywords[] = {"wit"};
static br_detector wit_detector = {
    .type = 817, .version = 0, .name = "Wit", .custom_name = "",
    .description = "Wit.ai is a natural language processing service that provides an API for building conversational interfaces. Wit.ai API keys can be used to access and modify this data and compute.",
    .keywords = wit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = wit_scan,
};

int br_wit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return wit_fail(error, "invalid Wit detector output");
    *out = NULL;
    if (br_key_pattern_init(&wit_detector, "\\b([A-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &wit_detector;
    return 0;
}
