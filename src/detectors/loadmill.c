/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/loadmill/loadmill.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct loadmill_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    struct loadmill_attempt *previous;
    char authorization[sizeof("Bearer ") + 40];
    unsigned char dedup_key[44];
} loadmill_attempt;

static int loadmill_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static loadmill_attempt *loadmill_request(const char *key)
{
    loadmill_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (loadmill_attempt){0};
    /* Captures are exactly 40 ASCII alphanumeric bytes. Retain the complete
     * type-and-credential namespace, not a credential-only key or hash. */
    memcpy(attempt->authorization, "Bearer ", 7);
    memcpy(attempt->authorization + 7, key, 40);
    memcpy(attempt->dedup_key, "758:", 4);
    memcpy(attempt->dedup_key + 4, key, 40);
    attempt->headers[0] = (br_header){"Accept", "application/vnd.loadmill+json; version=3"};
    attempt->headers[1] = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://app.loadmill.com/api/v1/labels?filter=CI_enable",
        .headers = attempt->headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 758,
        .dedup_key = {attempt->dedup_key, sizeof(attempt->dedup_key)},
    };
    return attempt;
}

static void loadmill_release(const br_scan_ctx *ctx, loadmill_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int loadmill_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return loadmill_fail(error, "invalid or uninitialized Loadmill scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    loadmill_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = loadmill_fail(error, "out of memory creating Loadmill result");
        if (rc == 0 && verify && !ctx) {
            /* Source's fixed-URL constructor skips before headers/auth, but
             * checked finding/map construction must already have succeeded. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            loadmill_attempt *attempt = loadmill_request(keys.items[i]);
            if (!attempt) rc = loadmill_fail(error, "out of memory creating Loadmill request");
            else {
                char *transport_error = NULL;
                /* An explicitly selected owned client buffers the raw body
                 * before success. Preserve borrowed keyed guards and suppress
                 * the whole shared preparation/Do domain without a setter. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else loadmill_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = loadmill_fail(error, "out of memory appending Loadmill result");
        br_result_clear(&result);
    }
    /* Raw owned-client releases already happened before send returned. Replay
     * closes are scan-deferred LIFO after publication, with provider originals
     * alive; only the owned raw snapshot extends synthesized preparation. */
    while (deferred) {
        loadmill_attempt *previous = deferred->previous;
        loadmill_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const loadmill_keywords[] = {"loadmill"};
static br_detector loadmill_detector = {
    .type = 758, .version = 0, .name = "Loadmill", .custom_name = "",
    .description = "Loadmill is a testing service for APIs and web applications. "
                   "Loadmill API keys can be used to access and manage test scenarios and results.",
    .keywords = loadmill_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = loadmill_scan,
};

int br_loadmill_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return loadmill_fail(error, "invalid Loadmill detector output");
    *out = NULL;
    if (br_key_pattern_init(&loadmill_detector, "\\b([0-9a-zA-Z]{40})\\b", error) != 0) return -1;
    *out = &loadmill_detector;
    return 0;
}
