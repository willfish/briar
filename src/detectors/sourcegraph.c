/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sourcegraph/sourcegraph.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SG_ABORT = -1, SG_KEEP = 0 } sg_outcome;

static int sg_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sg_metadata(br_result *result, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/sourcegraph/");
    if (!result->extra_data || !guide ||
        json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return sg_fail(error, "cannot create Sourcegraph metadata");
    }
    return 0;
}

static int sg_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return sg_fail(error, "cannot set Sourcegraph verification error");
    return 0;
}

static sg_outcome sg_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const unsigned char payload[] = "{\"query\": \"query { currentUser { username } }\"}";
    char authorization[sizeof("token ") + 128];
    if (key.len > sizeof(authorization) - sizeof("token ")) {
        sg_fail(error, "cannot format Sourcegraph authorization");
        return SG_ABORT;
    }
    memcpy(authorization, "token ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    /* Source adds headers before checking NewRequestWithContext. A nil context
     * makes that Header.Add panic, so this invocation fails instead of skipping. */
    if (!ctx) {
        sg_fail(error, "net/http: nil Context");
        return SG_ABORT;
    }
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://sourcegraph.com/.api/graphql",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            sg_fail(error, "cannot format Sourcegraph status");
            return SG_ABORT;
        }
        cause = status_error;
    }
    int rc = sg_cause(result, cause, key, error);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? SG_KEEP : SG_ABORT;
}

static int sg_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sg_fail(error, "invalid or uninitialized Sourcegraph scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        sg_outcome outcome = SG_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            sg_fail(&owned_error, "cannot create Sourcegraph result");
            outcome = SG_ABORT;
        } else if (sg_metadata(&result, &owned_error) != 0)
            outcome = SG_ABORT;
        else if (verify)
            outcome = sg_verify(ctx, key, &result, &owned_error);
        if (outcome == SG_ABORT) rc = -1;
        else if (br_results_push(out, &result) != 0) {
            sg_fail(&owned_error, "cannot append Sourcegraph result");
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

static const char *const sg_keywords[] = {"sgp_"};
static br_regex *sg_regex;
static br_detector sg_detector = {
    .type = 928, .version = 0, .name = "Sourcegraph", .custom_name = "",
    .description = "Sourcegraph is a code search and navigation engine. "
                   "Sourcegraph tokens can be used to access and interact with Sourcegraph APIs.",
    .keywords = sg_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sg_scan,
};

int br_sourcegraph_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sg_fail(error, "invalid Sourcegraph detector output");
    *out = NULL;
    if (!sg_regex && br_regex_compile(
            "\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b",
            &sg_regex, error) != 0)
        return -1;
    sg_detector.state = sg_regex;
    *out = &sg_detector;
    return 0;
}
