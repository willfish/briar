/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lendflow/lendflow.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int lendflow_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. The stack header array dies at send
 * return, so only the response and the original Bearer allocation are kept. */
typedef struct lendflow_pending lendflow_pending;
struct lendflow_pending {
    lendflow_pending *next;
    br_http_response response;
    char *authorization;
};

static int lendflow_retain(lendflow_pending **pending, const br_http_response *response,
                           char *authorization)
{
    lendflow_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->authorization = authorization;
    *pending = item;
    return 0;
}

/* Last success first, matching defer order at FromData return. The Bearer is
 * freed only after its own release. */
static void lendflow_release_held(const br_scan_ctx *ctx, lendflow_pending *pending)
{
    while (pending) {
        lendflow_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. A nil context is handled by the caller before this
 * allocation. Timeout is request-local; do not mutate a shared client. */
static int lendflow_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           lendflow_pending **pending, char **error)
{
    char *authorization = malloc(7 + 956 + 1);
    if (!authorization)
        return lendflow_fail(error, "cannot construct Lendflow authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 956);
    authorization[7 + 956] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
        {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://app.lendflow.io/api/v1/deals",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* Source never reads the body, so body_error cannot suppress a 2xx or drop
     * the finding. The whole mixed setup/Do domain stays unverified. Never set
     * a verification error. Do not retain the stack header array. */
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return 0;
    }
    if (lendflow_retain(pending, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return lendflow_fail(error, "cannot retain Lendflow response for release");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    return 0;
}

static int lendflow_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lendflow_fail(error, "invalid or uninitialized Lendflow scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lendflow_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* max_credential_span is an engine hint, not a scan cap. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede the constructor skip and any send. */
        if (key.len != 956)
            rc = lendflow_fail(&owned_error, "invalid Lendflow capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lendflow_fail(&owned_error, "cannot create Lendflow result");
        else if (verify && !ctx) {
            br_result_clear(&result);
            continue;
        } else if (verify && lendflow_verify(ctx, key, &result, &pending, &owned_error) != 0) {
            rc = -1;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = lendflow_fail(&owned_error, "cannot append Lendflow result");
        br_result_clear(&result);
    }
    /* Successful responses close after append, last success first. Fatal
     * construction, retention, finding, and push paths drain the same list
     * once, with each original Bearer still intact, then roll back only this
     * invocation. */
    lendflow_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const lendflow_keywords[] = {"lendflow"};
static const char lendflow_capture[] =
    "\\b([a-zA-Z0-9]{36}\\.[a-zA-Z0-9]{235}\\.[a-zA-Z0-9]{32}\\-[a-zA-Z0-9]{47}"
    "\\-[a-zA-Z0-9_]{162}\\-[a-zA-Z0-9]{42}\\-[a-zA-Z0-9_]{40}\\-[a-zA-Z0-9_]{66}"
    "\\-[a-zA-Z0-9_]{59}\\-[a-zA-Z0-9]{7}\\-[a-zA-Z0-9_]{220})\\b";
static br_detector lendflow_detector = {
    .type = 668, .version = 0, .name = "Lendflow", .custom_name = "",
    .description = "Lendflow is a platform for accessing financial data and services. Lendflow API keys can be used to access and manipulate this financial data.",
    .keywords = lendflow_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = lendflow_scan,
};

int br_lendflow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lendflow_fail(error, "invalid Lendflow detector output");
    *out = NULL;
    if (!lendflow_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(lendflow_keywords, 1, lendflow_capture, &regex, error) != 0)
            return -1;
        lendflow_detector.state = regex;
    }
    *out = &lendflow_detector;
    return 0;
}
