/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mindmeister/mindmeister.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct mindmeister_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct mindmeister_attempt *previous;
    char authorization[sizeof("Bearer ") + 43];
} mindmeister_attempt;

static int mindmeister_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static mindmeister_attempt *mindmeister_request(const char *key)
{
    mindmeister_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (mindmeister_attempt){0};
    memcpy(attempt->authorization, "Bearer ", 7);
    memcpy(attempt->authorization + 7, key, 43);
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://www.mindmeister.com/services/rest/oauth2?method=mm.maps.getList",
        .headers = &attempt->header, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 657,
    };
    return attempt;
}

static void mindmeister_release(const br_scan_ctx *ctx, mindmeister_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int mindmeister_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mindmeister_fail(error, "invalid or uninitialized Mindmeister scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    mindmeister_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the 43-byte ASCII alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mindmeister_fail(error, "out of memory creating Mindmeister result");
        if (rc == 0 && verify && !ctx) {
            /* Fixed-URL constructor skip follows checked finding construction
             * but precedes provider auth/header/request allocation. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            mindmeister_attempt *attempt = mindmeister_request(keys.items[i]);
            if (!attempt) rc = mindmeister_fail(error, "out of memory creating Mindmeister request");
            else {
                char *transport_error = NULL;
                int send_rc = br_http_send(ctx, &attempt->request, &attempt->response, &transport_error);
                if (send_rc == 0 && !attempt->response.body_error) {
                    /* ReadAll completes before search/status at EVERY status.
                     * Unlike a JSON decoder, any read error defeats all bytes. */
                    if (!attempt->response.body.data && attempt->response.body.len) {
                        rc = mindmeister_fail(error, "invalid Mindmeister response body slice");
                        mindmeister_release(ctx, attempt);
                    } else {
                        static const unsigned char marker[] = "\"stat\":\"ok\"";
                        bool valid = br_slice_find(attempt->response.body,
                            (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
                        result.verified = attempt->response.status >= 200 && attempt->response.status < 300 && valid;
                        attempt->previous = deferred;
                        deferred = attempt;
                    }
                } else {
                    /* Source installs no Close defer on Do/ReadAll failure
                     * and leaks a read-error body. ABI1 must still release once. */
                    mindmeister_release(ctx, attempt);
                }
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mindmeister_fail(error, "out of memory appending Mindmeister result");
        br_result_clear(&result);
    }
    /* Only successful full reads have source scan-deferred closes, including
     * non2xx and missing-marker responses. Retain provider originals, never
     * synthesized ordinary HTTP preparation storage, through LIFO release. */
    while (deferred) {
        mindmeister_attempt *previous = deferred->previous;
        mindmeister_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const mindmeister_keywords[] = {"mindmeister"};
static br_detector mindmeister_detector = {
    .type = 657, .version = 0, .name = "Mindmeister", .custom_name = "",
    .description = "Mindmeister is a mind mapping tool that helps users organize and visualize their thoughts. "
                   "Mindmeister API keys can be used to access and manipulate mind maps and other data within the platform.",
    .keywords = mindmeister_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mindmeister_scan,
};

int br_mindmeister_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mindmeister_fail(error, "invalid Mindmeister detector output");
    *out = NULL;
    if (br_key_pattern_init(&mindmeister_detector, "\\b([a-zA-Z0-9]{43})\\b", error) != 0) return -1;
    *out = &mindmeister_detector;
    return 0;
}
