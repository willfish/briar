/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/loyverse/loyverse.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char loyverse_bearer[] = "Bearer ";

typedef struct loyverse_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct loyverse_attempt *previous;
    char authorization[];
} loyverse_attempt;

static int loyverse_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static loyverse_attempt *loyverse_request(br_slice key)
{
    if (key.len > SIZE_MAX - sizeof(loyverse_attempt) - sizeof(loyverse_bearer)) return NULL;
    loyverse_attempt *attempt = malloc(sizeof(*attempt) + sizeof(loyverse_bearer) + key.len);
    if (!attempt) return NULL;
    *attempt = (loyverse_attempt){0};
    memcpy(attempt->authorization, loyverse_bearer, sizeof(loyverse_bearer) - 1);
    memcpy(attempt->authorization + sizeof(loyverse_bearer) - 1, key.data, key.len);
    attempt->authorization[sizeof(loyverse_bearer) - 1 + key.len] = '\0';
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://api.loyverse.com/v1.0/merchant/",
        .headers = &attempt->header, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 396,
    };
    return attempt;
}

static void loyverse_release(const br_scan_ctx *ctx, loyverse_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int loyverse_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return loyverse_fail(error, "invalid or uninitialized Loyverse scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    loyverse_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* The literal-hyphen/lowercase/digit grammar excludes TrimSpace bytes. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = loyverse_fail(error, "out of memory creating Loyverse result");
        if (rc == 0 && verify && !ctx) {
            /* The fixed-URL constructor rejects nil before source formats
             * Authorization. Checked finding construction still precedes it. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            loyverse_attempt *attempt = loyverse_request(key);
            if (!attempt) rc = loyverse_fail(error, "out of memory creating Loyverse request");
            else {
                char *transport_error = NULL;
                /* Suppress the whole mixed shared preparation/Do domain, not
                 * a diagnostic-text-selected subset. Source has no setter. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else loyverse_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = loyverse_fail(error, "out of memory appending Loyverse result");
        br_result_clear(&result);
    }
    /* Scan-deferred LIFO closes follow publication. Only provider originals
     * survive here; synthesized shared HTTP request/header/UA storage does not. */
    while (deferred) {
        loyverse_attempt *previous = deferred->previous;
        loyverse_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const loyverse_keywords[] = {"loyverse"};
static br_detector loyverse_detector = {
    .type = 396, .version = 0, .name = "Loyverse", .custom_name = "",
    .description = "Loyverse is a point of sale (POS) system that allows businesses to manage sales, inventory, and "
                   "customer relationships. Loyverse API keys can be used to access and modify this data.",
    .keywords = loyverse_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = loyverse_scan,
};

int br_loyverse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return loyverse_fail(error, "invalid Loyverse detector output");
    *out = NULL;
    if (br_key_pattern_init(&loyverse_detector, "\\b([0-9-a-z]{32})\\b", error) != 0) return -1;
    *out = &loyverse_detector;
    return 0;
}
