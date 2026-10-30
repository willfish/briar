/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sourcegraphcody/sourcegraphcody.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char sourcegraphcody_url[] = "https://cody-gateway.sourcegraph.com/v1/limits";

static int sourcegraphcody_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sourcegraphcody_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (key.len != 68) return sourcegraphcody_fail(error, "invalid SourcegraphCody capture");
    /* Header.Add runs before the constructor error check. A nil context panics
     * rather than skipping the candidate or retaining a verification error. */
    if (!ctx)
        return sourcegraphcody_fail(error, "unsupported upstream panic: SourcegraphCody nil request before Header.Add");
    char authorization[7 + 68 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 68);
    authorization[75] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = sourcegraphcody_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = sourcegraphcody_fail(error, "cannot format SourcegraphCody status");
        else cause = status_error;
    }
    /* Close only; a body_error cannot change a completed response. */
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = sourcegraphcody_fail(error, "cannot set SourcegraphCody verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int sourcegraphcody_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sourcegraphcody_fail(error, "invalid or uninitialized SourcegraphCody scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = sourcegraphcody_fail(&owned_error, "cannot create SourcegraphCody result");
        else if (verify && sourcegraphcody_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = sourcegraphcody_fail(&owned_error, "cannot append SourcegraphCody result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sourcegraphcody_keywords[] = {"slk_"};
static br_detector sourcegraphcody_detector = {
    .type = 936, .version = 0, .name = "SourcegraphCody", .custom_name = "",
    .description = "Sourcegraph Cody is a tool for integrating code intelligence into your development workflow. The detected key is used for accessing Sourcegraph Cody services.",
    .keywords = sourcegraphcody_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sourcegraphcody_scan,
};

int br_sourcegraphcody_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sourcegraphcody_fail(error, "invalid SourcegraphCody detector output");
    *out = NULL;
    if (!sourcegraphcody_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(slk_[a-f0-9]{64})\\b", &regex, error) != 0) return -1;
        sourcegraphcody_detector.state = regex;
    }
    *out = &sourcegraphcody_detector;
    return 0;
}
