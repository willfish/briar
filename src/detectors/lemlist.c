/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lemlist/lemlist.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    LEMLIST_ABORT = -1,
    LEMLIST_KEEP = 0,
    LEMLIST_DROP = 1
} lemlist_outcome;

typedef struct lemlist_pending lemlist_pending;
struct lemlist_pending {
    lemlist_pending *next;
    br_http_response response;
    char *authorization;
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful responses close LIFO after publication. Free Basic only then. */
static void release_pending(const br_scan_ctx *ctx, lemlist_pending *pending)
{
    while (pending) {
        lemlist_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* ABORT is any owned encoder or retain failure, including +1, even with a nil
 * context. DROP is only a successful encode followed by the constructor skip. */
static lemlist_outcome verify_lemlist(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                      lemlist_pending **pending, char **error)
{
    char *authorization = NULL;
    /* Empty username and the raw key. Colon-plus-key and Base64 precede the constructor. */
    if (br_http_basic_auth((br_slice){0}, key, &authorization, error) != 0) {
        free(authorization);
        return LEMLIST_ABORT;
    }
    if (!ctx) {
        free(authorization);
        return LEMLIST_DROP; /* No send and no release. This skip is not an attempt. */
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.lemlist.com/api/team",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* The whole mixed setup/Do domain stays unverified. Do not classify its
     * text, set a verification error, or read the body. Failed attempts close now. */
    if (sent != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return LEMLIST_KEEP;
    }
    result->verified = response.status >= 200 && response.status < 300;
    lemlist_pending *node = malloc(sizeof(*node));
    if (!node) {
        br_http_release(ctx, &response);
        free(authorization);
        fail(error, "cannot retain Lemlist response for release");
        return LEMLIST_ABORT;
    }
    node->response = response;
    node->authorization = authorization;
    node->next = *pending;
    *pending = node;
    return LEMLIST_KEEP;
}

static int scan_lemlist(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Lemlist scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lemlist_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        lemlist_outcome outcome = LEMLIST_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* Keep every in-range occurrence, including duplicates. Encode only
         * after the finding exists and only when verification is on. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Lemlist finding");
            outcome = LEMLIST_ABORT;
        } else if (verify)
            outcome = verify_lemlist(ctx, key, &result, &pending, &owned_error);
        if (outcome == LEMLIST_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Lemlist finding");
            outcome = LEMLIST_ABORT;
        }
        br_result_clear(&result);
        if (outcome == LEMLIST_ABORT) rc = -1;
    }
    /* Publication precedes these closes, including a later rollback. */
    release_pending(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"lemlist"};
static br_detector lemlist = {
    .type = 841,
    .version = 0,
    .name = "Lemlist",
    .custom_name = "",
    .description = "Lemlist is an email outreach platform used for sending personalized emails. Lemlist API keys can be used to access and manage email campaigns and contacts.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_lemlist,
};

int br_lemlist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Lemlist detector output");
    *out = NULL;
    if (!lemlist.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-f0-9]{32})\\b", &regex, error) != 0)
            return -1;
        lemlist.state = regex;
    }
    *out = &lemlist;
    return 0;
}
