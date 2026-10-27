/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/closecrm/close.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum { CLOSE_ABORT = -1, CLOSE_KEEP = 0, CLOSE_SKIP = 1 } close_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static close_outcome verify_close(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char *authorization = NULL;
    /* Source prepares Base64(KEY+":") BEFORE the context-bound constructor.
     * Helper +1 is a fatal resource failure, never a constructor skip/Do error. */
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error)) { free(authorization); return CLOSE_ABORT; }
    if (!ctx) { free(authorization); return CLOSE_SKIP; }
    const br_header headers[] = {{"Authorization", authorization}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.close.com/api/v1/me/",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source suppresses every Client.Do error. ABI1 also mixes adapter setup
     * and allocation failures here; do not infer stages from error text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* All body/read errors are ignored. Source scan-defers Close ONLY; native
     * eager buffering/per-request release and client configuration stay partial. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization); /* Borrowed header lives through release. */
    return CLOSE_KEEP;
}

static int scan_close(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Close scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; close_outcome outcome = CLOSE_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace does not change this ASCII capture; retain every byte,
         * including a final dot accepted by the source's word boundary. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Close result"); outcome = CLOSE_ABORT;
        }
        if (outcome == CLOSE_KEEP && verify) outcome = verify_close(ctx, key, &result, &owned_error);
        if (outcome == CLOSE_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Close result"); outcome = CLOSE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CLOSE_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"close"};
static br_detector close_detector = {
    .type = 215, .version = 0, .name = "Close", .custom_name = "",
    .description = "Close is a CRM software that helps businesses manage sales and customer relationships. Close API keys can be used to access and manipulate CRM data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_close,
};

int br_closecrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Close detector output");
    *out = NULL;
    /* DIRECT extraction: descriptor keyword is dispatch-only, not a prefix. */
    if (!close_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(api_[a-z0-9A-Z.]{45})\\b", &pattern, error)) return -1;
        close_detector.state = pattern;
    }
    *out = &close_detector;
    return 0;
}
