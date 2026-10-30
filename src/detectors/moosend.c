/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/moosend/moosend.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int moosend_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Exact bytes only. Call this only for a reached body. */
static bool contains_created_on(br_slice body)
{
    static const char needle[] = "CreatedOn";
    if (!body.data || body.len < sizeof(needle) - 1) return false;
    for (size_t i = 0; i + sizeof(needle) - 1 <= body.len; ++i)
        if (!memcmp(body.data + i, needle, sizeof(needle) - 1)) return true;
    return false;
}

/* Successful Do closes are scan-deferred. A stack URL cannot survive that
 * release, so the original allocation stays with the response. */
typedef struct moosend_pending moosend_pending;
struct moosend_pending {
    moosend_pending *next;
    br_http_response response;
    char *url;
};

static int moosend_retain(moosend_pending **pending, const br_http_response *response, char *url)
{
    moosend_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->url = url;
    *pending = item;
    return 0;
}

static void moosend_release_held(const br_scan_ctx *ctx, moosend_pending *pending)
{
    while (pending) {
        moosend_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->url);
        free(pending);
        pending = next;
    }
}

/* The complete literal URL is owned before the nil-context check. No encoding.
 * 1 drops this occurrence. 0 publishes it. Any other status, including +1, is
 * fatal. There is no setter and no provider header. */
static int moosend_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                          moosend_pending **pending, char **error)
{
    static const char prefix[] = "https://api.moosend.com/v3/lists.json?apikey=";
    static const char suffix[] = "&format=json";
    char *url = malloc(sizeof(prefix) - 1 + 36 + sizeof(suffix));
    if (!url) return moosend_fail(error, "cannot allocate Moosend URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 36);
    memcpy(url + sizeof(prefix) - 1 + 36, suffix, sizeof(suffix));
    if (!ctx) {
        free(url);
        return 1;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    /* Setup and Do errors stay unverified. Do not inspect the body or invent a cause. */
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(url);
        return 0;
    }
    if (moosend_retain(pending, &response, url) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return moosend_fail(error, "cannot retain Moosend response for release");
    }
    /* ReadAll failure drops without a search. The response stays deferred. */
    if (response.body_error) return 1;
    if (!response.body.data && response.body.len)
        return moosend_fail(error, "invalid Moosend response body");
    /* Status is irrelevant. A missing needle stays unverified and is kept. */
    result->verified = contains_created_on(response.body);
    return 0;
}

static int moosend_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return moosend_fail(error, "invalid or uninitialized Moosend scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    moosend_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Do not fold the first group's A. Keep every
         * occurrence. Finding resources precede URL construction. */
        if (key.len != 36)
            rc = moosend_fail(&owned_error, "invalid Moosend capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = moosend_fail(&owned_error, "cannot create Moosend result");
        else if (verify) {
            int verdict = moosend_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict == 1) keep = false;
            else if (verdict != 0) rc = -1;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = moosend_fail(&owned_error, "cannot append Moosend result");
        br_result_clear(&result);
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    moosend_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const moosend_keywords[] = {"moosend"};
static br_detector moosend_detector = {
    .type = 261, .version = 0, .name = "Moosend", .custom_name = "",
    .description = "Moosend is an email marketing service provider. Moosend API keys can be used to access and manage email marketing campaigns, subscriber lists, and other related data.",
    .keywords = moosend_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = moosend_scan,
};

int br_moosend_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return moosend_fail(error, "invalid Moosend detector output");
    *out = NULL;
    if (!moosend_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(moosend_keywords, 1,
                                      "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                                      &regex, error) != 0)
            return -1;
        moosend_detector.state = regex;
    }
    *out = &moosend_detector;
    return 0;
}
