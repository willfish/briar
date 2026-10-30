/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/webflow/webflow.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { WF_ABORT = -1, WF_KEEP = 0, WF_DROP = 1 } wf_outcome;

static int wf_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static wf_outcome wf_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return WF_DROP;
    if (strlen(key) != 64) return wf_fail(error, "unexpected Webflow key length"), WF_ABORT;
    char authorization[7 + 64 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 65);
    /* Header.Add("accept-version") is canonicalized to Accept-Version. */
    const br_header headers[] = {
        {"Accept-Version", "1.0.0"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.webflow.com/info",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return WF_KEEP;
}

static int wf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return wf_fail(error, "invalid or uninitialized Webflow scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        wf_outcome outcome = WF_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = wf_fail(&owned_error, "cannot create Webflow result");
        else if (verify)
            outcome = wf_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == WF_ABORT) rc = -1;
        if (rc == 0 && outcome == WF_KEEP && br_results_push(out, &result) != 0)
            rc = wf_fail(&owned_error, "cannot append Webflow result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const wf_keywords[] = {"webflow"};
static br_detector wf_detector = {
    .type = 218, .version = 0, .name = "Webflow", .custom_name = "",
    .description = "Webflow is a web design tool that allows users to design, build, and launch responsive websites visually. Webflow API keys can be used to access and manipulate data within Webflow projects.",
    .keywords = wf_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = wf_scan,
};

int br_webflow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return wf_fail(error, "invalid Webflow detector output");
    *out = NULL;
    if (br_key_pattern_init(&wf_detector, "\\b([a-zA0-9]{64})\\b", error) != 0) return -1;
    *out = &wf_detector;
    return 0;
}
