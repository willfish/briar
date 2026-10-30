/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rootly/rootly.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char rootly_url[] = "https://api.rootly.com/v1/incidents";

static int rootly_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int rootly_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (key.len != 71) return rootly_fail(error, "invalid Rootly capture");
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1)
            ? rootly_fail(error, "cannot set Rootly verification error") : 0;
    char authorization[7 + 71 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 71);
    authorization[78] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = rootly_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200 || response.status == 404)
        result->verified = true; /* 404 means the token is valid but has no incidents. */
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = rootly_fail(error, "cannot format Rootly status");
        else cause = status_error;
    }
    /* Source closes without reading. A body_error cannot change the verdict. */
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = rootly_fail(error, "cannot set Rootly verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int rootly_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return rootly_fail(error, "invalid or uninitialized Rootly scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = rootly_fail(&owned_error, "cannot create Rootly result");
        else if (verify && rootly_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = rootly_fail(&owned_error, "cannot append Rootly result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rootly_keywords[] = {"rootly_"};
static br_detector rootly_detector = {
    .type = 1035, .version = 0, .name = "Rootly", .custom_name = "",
    .description = "Rootly is an incident management platform. Rootly API keys can be used to access and manage incident data and other services.",
    .keywords = rootly_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = rootly_scan,
};

int br_rootly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rootly_fail(error, "invalid Rootly detector output");
    *out = NULL;
    if (!rootly_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(rootly_[a-f0-9]{64})\\b", &regex, error) != 0) return -1;
        rootly_detector.state = regex;
    }
    *out = &rootly_detector;
    return 0;
}
