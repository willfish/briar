/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/omnisend/omnisend.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct omnisend_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct omnisend_attempt *previous;
} omnisend_attempt;

static int omnisend_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static omnisend_attempt *omnisend_request(const char *key)
{
    omnisend_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (omnisend_attempt){0};
    /* Go Header.Add canonicalizes the source X-API-KEY spelling. */
    attempt->header = (br_header){"X-Api-Key", key};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://api.omnisend.com/v3/contacts?limit=100&offset=0",
        .headers = &attempt->header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 205,
    };
    return attempt;
}

static void omnisend_release(const br_scan_ctx *ctx, omnisend_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int omnisend_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return omnisend_fail(error, "invalid or uninitialized Omnisend scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    omnisend_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op for the ASCII alphanumeric/hyphen grammar. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = omnisend_fail(error, "cannot create Omnisend result");
        if (rc == 0 && verify && !ctx) {
            /* Fixed-URL constructor drops before provider request/header
             * allocation, but never hides a reached finding/map failure. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            /* One checked frame owns both request and deferred-close storage. */
            omnisend_attempt *attempt = omnisend_request(keys.items[i]);
            if (!attempt) rc = omnisend_fail(error, "cannot create Omnisend request");
            else {
                char *transport_error = NULL;
                /* Suppress the WHOLE mixed shared prep/Do domain, regardless of
                 * diagnostic text. Source has NO setter and ignores bodies and
                 * every body_error after Do success. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else omnisend_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = omnisend_fail(error, "cannot append Omnisend result");
        br_result_clear(&result);
    }
    /* Successful closes are SCAN-wide LIFO after publication, also on fatal
     * exits. Provider original request/header/key frames survive release;
     * ordinary synthesized request/header-array/UA expires at send return. */
    while (deferred) {
        omnisend_attempt *previous = deferred->previous;
        omnisend_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const omnisend_keywords[] = {"omnisend"};
static br_detector omnisend_detector = {
    .type = 205, .version = 0, .name = "Omnisend", .custom_name = "",
    .description = "Omnisend is a marketing automation platform focused on e-commerce. Omnisend API keys can be used to access and manage marketing campaigns, contacts, and other resources within the Omnisend platform.",
    .keywords = omnisend_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = omnisend_scan,
};

int br_omnisend_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return omnisend_fail(error, "invalid Omnisend detector output");
    *out = NULL;
    if (br_key_pattern_init(&omnisend_detector, "\\b([a-z0-9A-Z-]{75})\\b", error) != 0) return -1;
    *out = &omnisend_detector;
    return 0;
}
