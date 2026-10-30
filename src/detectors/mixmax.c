/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mixmax/mixmax.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mixmax_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct mixmax_pending mixmax_pending;
struct mixmax_pending {
    mixmax_pending *next;
    br_http_request request;
    br_http_response response;
    br_header header;
    unsigned char dedup_key[41];
};

static void mixmax_release(const br_scan_ctx *ctx, mixmax_pending *pending)
{
    while (pending) {
        mixmax_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending);
        pending = next;
    }
}

static int mixmax_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mixmax_fail(error, "invalid or uninitialized Mixmax scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    mixmax_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 36 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mixmax_fail(&owned_error, "cannot create Mixmax result");
        if (rc == 0 && verify) {
            /* Fixed-URL constructor failure drops only after checked finding
             * creation, before source-unreached header/dedup construction. */
            if (!ctx) { br_result_clear(&result); continue; }
            mixmax_pending *attempt = malloc(sizeof(*attempt));
            if (!attempt) rc = mixmax_fail(&owned_error, "cannot construct Mixmax request");
            else {
                *attempt = (mixmax_pending){0};
                attempt->header = (br_header){"X-Api-Token", (const char *)key.data};
                memcpy(attempt->dedup_key, "700:", 4);
                memcpy(attempt->dedup_key + 4, key.data, key.len);
                attempt->dedup_key[40] = 0;
                attempt->request = (br_http_request){
                    .method = "GET", .url = "https://api.mixmax.com/v1/users/me",
                    .headers = &attempt->header, .nheaders = 1,
                    .profile = BR_HTTP_SANE, .detector_type = detector->type,
                    .dedup_key = {attempt->dedup_key, 40},
                };
                char *send_error = NULL;
                /* The selected client owns buffering and its flight namespace.
                 * Borrowed keyed transports must still hit the shared guard. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->next = pending;
                    pending = attempt;
                } else {
                    /* Suppress the WHOLE mixed shared preparation/Do domain,
                     * including buffering errors, with no setter/text classifier. */
                    mixmax_release(ctx, attempt);
                }
                free(send_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mixmax_fail(&owned_error, "cannot append Mixmax result");
        br_result_clear(&result);
    }
    /* Raw owned-client bodies close before Do returns. Successful replay closes
     * are scan-deferred LIFO after publication. Provider request/header/key bytes
     * survive release; no ordinary synthesized preparation storage is retained. */
    mixmax_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mixmax_keywords[] = {"mixmax"};
static br_detector mixmax_detector = {
    .type = 700, .version = 0, .name = "Mixmax", .custom_name = "",
    .description = "Mixmax is a communication platform for email enhancement and automation. Mixmax API tokens can be used to access and manage email communication and automation features.",
    .keywords = mixmax_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mixmax_scan,
};

int br_mixmax_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mixmax_fail(error, "invalid Mixmax detector output");
    *out = NULL;
    if (!mixmax_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(mixmax_keywords, 1, "\\b([a-zA-Z0-9_-]{36})\\b", &regex, error) != 0) return -1;
        mixmax_detector.state = regex;
    }
    *out = &mixmax_detector;
    return 0;
}
