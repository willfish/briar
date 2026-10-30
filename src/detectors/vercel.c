/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/vercel/vercel.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { VC_ABORT = -1, VC_KEEP = 0, VC_DROP = 1 } vc_outcome;

static int vc_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static vc_outcome vc_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return VC_DROP;
    if (key.len != 24) return vc_fail(error, "unexpected Vercel key length"), VC_ABORT;
    char authorization[7 + 24 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 24);
    authorization[31] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.vercel.com/www/user",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return VC_KEEP;
}

static int vc_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return vc_fail(error, "invalid or uninitialized Vercel scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        vc_outcome outcome = VC_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = vc_fail(&owned_error, "cannot create Vercel result");
        else if (verify)
            outcome = vc_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && outcome == VC_ABORT) rc = -1;
        if (rc == 0 && outcome == VC_KEEP && br_results_push(out, &result) != 0)
            rc = vc_fail(&owned_error, "cannot append Vercel result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const vc_keywords[] = {"vercel"};
static br_detector vc_detector = {
    .type = 160, .version = 0, .name = "Vercel", .custom_name = "",
    .description = "Vercel is a platform for frontend frameworks and static sites, built to integrate with your headless content, commerce, or database. Vercel API keys can be used to access and manage your Vercel projects and deployments.",
    .keywords = vc_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = vc_scan,
};

int br_vercel_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return vc_fail(error, "invalid Vercel detector output");
    *out = NULL;
    if (br_key_pattern_init(&vc_detector, "\\b([a-zA-Z0-9]{24})\\b", error) != 0) return -1;
    *out = &vc_detector;
    return 0;
}
