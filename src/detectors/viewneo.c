/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/viewneo/viewneo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum { VIEW_KEEP = 0, VIEW_DROP = 1, VIEW_FATAL = -1 };

static int view_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return VIEW_FATAL;
}

static int view_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return VIEW_DROP;
    if (memchr(key.data, '\0', key.len) || key.len > INT_MAX)
        return view_fail(error, "unsupported: Viewneo key cannot be an Authorization value");
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) return view_fail(error, "cannot allocate Viewneo Authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://cloud.viewneo.com/api/v1.0/playlist",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return VIEW_KEEP;
}

static int view_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return view_fail(error, "invalid or uninitialized Viewneo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = VIEW_KEEP;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            outcome = view_fail(&owned_error, "cannot create Viewneo result");
        else if (verify)
            outcome = view_verify(ctx, br_captures_at(&keys, i), &result, &owned_error);
        if (outcome == VIEW_FATAL) rc = -1;
        if (outcome == VIEW_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = view_fail(&owned_error, "cannot append Viewneo result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const view_keywords[] = {"viewneo"};
static br_detector view_detector = {
    .type = 706, .version = 0, .name = "Viewneo", .custom_name = "",
    .description = "Viewneo is a digital signage platform. Viewneo API keys can be used to access and manage digital signage content and settings.",
    .keywords = view_keywords, .nkeywords = 1,
    .max_secret_size = 1500, .start_offset = -1, .max_credential_span = -1,
    .scan = view_scan,
};

int br_viewneo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return view_fail(error, "invalid Viewneo detector output");
    *out = NULL;
    /* Both dots are any non-LF byte. There is no trailing word boundary. */
    if (br_key_pattern_init(&view_detector,
                            "\\b([a-z0-9A-Z]{120,300}.[a-z0-9A-Z]{150,300}.[a-z0-9A-Z-_]{600,800})",
                            error) != 0)
        return -1;
    *out = &view_detector;
    return 0;
}
