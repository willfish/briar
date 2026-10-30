/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lunchmoney/lunchmoney.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char lunchmoney_bearer[] = "Bearer ";

typedef struct lunchmoney_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct lunchmoney_attempt *previous;
    char authorization[];
} lunchmoney_attempt;

static int lunchmoney_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static lunchmoney_attempt *lunchmoney_request(br_slice key)
{
    if (key.len > SIZE_MAX - sizeof(lunchmoney_attempt) - sizeof(lunchmoney_bearer)) return NULL;
    lunchmoney_attempt *attempt = malloc(sizeof(*attempt) + sizeof(lunchmoney_bearer) + key.len);
    if (!attempt) return NULL;
    *attempt = (lunchmoney_attempt){0};
    memcpy(attempt->authorization, lunchmoney_bearer, sizeof(lunchmoney_bearer) - 1);
    memcpy(attempt->authorization + sizeof(lunchmoney_bearer) - 1, key.data, key.len);
    attempt->authorization[sizeof(lunchmoney_bearer) - 1 + key.len] = '\0';
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://dev.lunchmoney.app/v1/categories",
        .headers = &attempt->header, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 797,
    };
    return attempt;
}

static void lunchmoney_release(const br_scan_ctx *ctx, lunchmoney_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int lunchmoney_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lunchmoney_fail(error, "invalid or uninitialized LunchMoney scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lunchmoney_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase-hex capture. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lunchmoney_fail(error, "out of memory creating LunchMoney result");
        if (rc == 0 && verify && !ctx) {
            /* With this fixed URL, source's nil-context constructor skip is
             * after finding construction but before formatting Authorization. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            lunchmoney_attempt *attempt = lunchmoney_request(key);
            if (!attempt) rc = lunchmoney_fail(error, "out of memory creating LunchMoney request");
            else {
                char *transport_error = NULL;
                /* Source suppresses the entire mixed preparation/Do domain.
                 * Neither error text nor sign identifies a module failure. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else lunchmoney_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = lunchmoney_fail(error, "out of memory appending LunchMoney result");
        br_result_clear(&result);
    }
    /* Source closes successful responses LIFO after publishing findings.
     * Retain provider originals, never synthesized shared preparation storage. */
    while (deferred) {
        lunchmoney_attempt *previous = deferred->previous;
        lunchmoney_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const lunchmoney_keywords[] = {"lunchmoney"};
static br_detector lunchmoney_detector = {
    .type = 797, .version = 0, .name = "LunchMoney", .custom_name = "",
    .description = "LunchMoney is a personal finance tool that helps users manage their finances. "
                   "LunchMoney API keys can be used to access and modify financial data.",
    .keywords = lunchmoney_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lunchmoney_scan,
};

int br_lunchmoney_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lunchmoney_fail(error, "invalid LunchMoney detector output");
    *out = NULL;
    if (br_key_pattern_init(&lunchmoney_detector, "\\b([a-f0-9]{50})\\b", error) != 0) return -1;
    *out = &lunchmoney_detector;
    return 0;
}
