/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/miro/miro.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int miro_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct miro_pending miro_pending;
struct miro_pending {
    miro_pending *next;
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    char authorization[sizeof("Bearer ") - 1 + 27 + 1];
};

static void miro_release(const br_scan_ctx *ctx, miro_pending *pending)
{
    while (pending) {
        miro_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending);
        pending = next;
    }
}

static int miro_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return miro_fail(error, "invalid or uninitialized Miro scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    miro_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 27 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = miro_fail(&owned_error, "cannot create Miro result");
        if (rc == 0 && verify) {
            /* Fixed-URL NewRequestWithContext drops the already-created
             * finding on nil context, before either header/auth construction. */
            if (!ctx) { br_result_clear(&result); continue; }
            miro_pending *attempt = malloc(sizeof(*attempt));
            if (!attempt) rc = miro_fail(&owned_error, "cannot construct Miro request");
            else {
                *attempt = (miro_pending){0};
                attempt->headers[0] = (br_header){"Accept", "application/json"};
                memcpy(attempt->authorization, "Bearer ", 7);
                memcpy(attempt->authorization + 7, key.data, key.len);
                attempt->authorization[7 + key.len] = 0;
                attempt->headers[1] = (br_header){"Authorization", attempt->authorization};
                attempt->request = (br_http_request){
                    .method = "GET", .url = "https://api.miro.com/v1/users/me",
                    .headers = attempt->headers, .nheaders = 2,
                    .profile = BR_HTTP_SANE, .detector_type = detector->type,
                };
                char *send_error = NULL;
                if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->next = pending;
                    pending = attempt;
                } else {
                    /* Source suppresses the WHOLE mixed preparation/Do error
                     * domain, without a setter or diagnostic classification. */
                    miro_release(ctx, attempt);
                }
                free(send_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = miro_fail(&owned_error, "cannot append Miro result");
        br_result_clear(&result);
    }
    /* Successful closes are scan-deferred LIFO after publication, with original
     * request/header/auth/key storage alive. Synthesized prepared headers/UA
     * end at send return; all response body/read errors are ignored. */
    miro_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const miro_keywords[] = {"miro"};
static br_detector miro_detector = {
    .type = 774, .version = 0, .name = "Miro", .custom_name = "",
    .description = "Miro is an online collaborative whiteboarding platform. Miro API keys can be used to access and modify data and collaborate on whiteboards.",
    .keywords = miro_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = miro_scan,
};

int br_miro_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return miro_fail(error, "invalid Miro detector output");
    *out = NULL;
    if (!miro_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(miro_keywords, 1, "\\b([0-9a-zA-Z]{27})\\b", &regex, error) != 0) return -1;
        miro_detector.state = regex;
    }
    *out = &miro_detector;
    return 0;
}
