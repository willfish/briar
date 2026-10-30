/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pipedream/pipedream.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int pipedream_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct pipedream_pending pipedream_pending;
struct pipedream_pending {
    pipedream_pending *next;
    br_http_request request;
    br_http_response response;
    br_header authorization_header;
    char authorization[7 + 32 + 1];
};

static void pipedream_release(const br_scan_ctx *ctx, pipedream_pending *pending)
{
    while (pending) {
        pipedream_pending *next = pending->next;
        /* Release while the provider URL, header, and key storage still live.
         * Ordinary prepared request, header-array, and UA storage ends at send. */
        br_http_release(ctx, &pending->response);
        free(pending);
        pending = next;
    }
}

static int pipedream_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pipedream_fail(error, "invalid or uninitialized Pipedream scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    pipedream_pending *pending = NULL;
    char *owned_error = NULL;
    /* Duplicates and source order are retained. TrimSpace cannot widen this
     * bounded lowercase capture, so the captured bytes are the key. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pipedream_fail(&owned_error, "cannot create Pipedream result");
        if (rc == 0 && verify) {
            /* Checked finding precedes the nil-context drop. Source continues
             * without appending, without a setter, and before request storage. */
            if (!ctx) {
                keep = false;
            } else {
                pipedream_pending *attempt = malloc(sizeof(*attempt));
                if (!attempt) {
                    rc = pipedream_fail(&owned_error, "cannot construct Pipedream request");
                } else {
                    *attempt = (pipedream_pending){0};
                    memcpy(attempt->authorization, "Bearer ", 7);
                    memcpy(attempt->authorization + 7, key.data, key.len);
                    attempt->authorization[7 + key.len] = 0;
                    attempt->authorization_header = (br_header){"Authorization", attempt->authorization};
                    /* Source assigns 15s on its package SANE client. Project that
                     * onto this request only; do not mutate a process-global client. */
                    attempt->request = (br_http_request){
                        .method = "GET", .url = "https://api.pipedream.com/v1/users/me",
                        .headers = &attempt->authorization_header, .nheaders = 1,
                        .profile = BR_HTTP_SANE, .timeout_ms = 15000,
                        .detector_type = detector->type,
                    };
                    char *send_error = NULL;
                    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
                        /* No body read. Every 2xx is verified despite body_error. */
                        result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                        attempt->next = pending;
                        pending = attempt;
                    } else {
                        /* The whole preparation/Do domain stays false: no scan
                         * error, no setter, and one immediate release. */
                        pipedream_release(ctx, attempt);
                    }
                    free(send_error);
                }
            }
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = pipedream_fail(&owned_error, "cannot append Pipedream result");
        br_result_clear(&result);
    }
    /* Successful closes, including non-2xx, are scan-wide LIFO after publication. */
    pipedream_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pipedream_keywords[] = {"pipedream"};
static br_detector pipedream_detector = {
    .type = 724, .version = 0, .name = "Pipedream", .custom_name = "",
    .description = "Pipedream is an integration platform for developers to build and run workflows that integrate apps, data, and APIs. Pipedream API keys can be used to access and modify these workflows and data.",
    .keywords = pipedream_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pipedream_scan,
};

int br_pipedream_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pipedream_fail(error, "invalid Pipedream detector output");
    *out = NULL;
    if (!pipedream_detector.state) {
        br_regex *regex = NULL;
        /* Keyword-only case folding and a lazy 0..40-unit gap, then the key. */
        if (br_regex_compile_prefixed(pipedream_keywords, 1, "\\b([a-z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        pipedream_detector.state = regex;
    }
    *out = &pipedream_detector;
    return 0;
}
