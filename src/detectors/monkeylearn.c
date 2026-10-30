/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/monkeylearn/monkeylearn.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct monkeylearn_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    struct monkeylearn_attempt *previous;
    char authorization[sizeof("Token ") + 40];
} monkeylearn_attempt;

static int monkeylearn_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static monkeylearn_attempt *monkeylearn_request(const char *key)
{
    monkeylearn_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (monkeylearn_attempt){0};
    /* Source uses Token, not Bearer, with an exact 40-byte lowercase-hex key. */
    memcpy(attempt->authorization, "Token ", 6);
    memcpy(attempt->authorization + 6, key, 40);
    attempt->headers[0] = (br_header){"Accept", "application/json"};
    attempt->headers[1] = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://api.monkeylearn.com/v3/classifiers",
        .headers = attempt->headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 820,
    };
    return attempt;
}

static void monkeylearn_release(const br_scan_ctx *ctx, monkeylearn_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int monkeylearn_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return monkeylearn_fail(error, "invalid or uninitialized MonkeyLearn scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    monkeylearn_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase-hex capture. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = monkeylearn_fail(error, "out of memory creating MonkeyLearn result");
        if (rc == 0 && verify && !ctx) {
            /* Fixed-URL constructor skip follows checked finding/maps but
             * precedes source-unreached Token/header/request allocation. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            monkeylearn_attempt *attempt = monkeylearn_request(keys.items[i]);
            if (!attempt) rc = monkeylearn_fail(error, "out of memory creating MonkeyLearn request");
            else {
                char *transport_error = NULL;
                /* Suppress the entire mixed shared preparation/Do domain.
                 * Source has no setter and ignores all body/read errors. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else monkeylearn_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = monkeylearn_fail(error, "out of memory appending MonkeyLearn result");
        br_result_clear(&result);
    }
    /* Source closes successful responses LIFO after publication. Only provider
     * request/header/auth/key storage survives here, never ordinary prepared
     * shared HTTP request/header-array/User-Agent allocations. */
    while (deferred) {
        monkeylearn_attempt *previous = deferred->previous;
        monkeylearn_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const monkeylearn_keywords[] = {"monkeylearn"};
static br_detector monkeylearn_detector = {
    .type = 820, .version = 0, .name = "MonkeyLearn", .custom_name = "",
    .description = "MonkeyLearn is a machine learning platform that allows you to analyze text with custom machine learning "
                   "models. API keys can be used to access and manage these models.",
    .keywords = monkeylearn_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = monkeylearn_scan,
};

int br_monkeylearn_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return monkeylearn_fail(error, "invalid MonkeyLearn detector output");
    *out = NULL;
    if (br_key_pattern_init(&monkeylearn_detector, "\\b([0-9a-f]{40})\\b", error) != 0) return -1;
    *out = &monkeylearn_detector;
    return 0;
}
