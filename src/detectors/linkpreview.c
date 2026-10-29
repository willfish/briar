/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/linkpreview/linkpreview.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int linkpreview_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. A stack URL cannot survive that
 * release, so the original allocation stays with the response. */
typedef struct linkpreview_pending linkpreview_pending;
struct linkpreview_pending {
    linkpreview_pending *next;
    br_http_response response;
    char *url;
};

static int linkpreview_retain(linkpreview_pending **pending, const br_http_response *response, char *url)
{
    linkpreview_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->url = url;
    *pending = item;
    return 0;
}

static void linkpreview_release_held(const br_scan_ctx *ctx, linkpreview_pending *pending)
{
    while (pending) {
        linkpreview_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->url);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. The complete literal URL is owned before the
 * nil-context drop. 1 drops this occurrence. 0 publishes it. -1 is fatal.
 * There is no setter and no provider header. */
static int linkpreview_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              linkpreview_pending **pending, char **error)
{
    static const char prefix[] = "https://api.linkpreview.net/?key=";
    static const char suffix[] = "&q=https://google.com";
    char *url = malloc(sizeof(prefix) - 1 + 32 + sizeof(suffix));
    if (!url) return linkpreview_fail(error, "cannot allocate LinkPreview URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
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
    /* Setup and Do errors stay unverified. Do not invent a verification cause. */
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(url);
        return 0;
    }
    if (linkpreview_retain(pending, &response, url) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return linkpreview_fail(error, "cannot retain LinkPreview response for release");
    }
    /* Source never reads the body, so body_error cannot suppress a 2xx or drop it. */
    result->verified = response.status >= 200 && response.status < 300;
    return 0;
}

static int linkpreview_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return linkpreview_fail(error, "invalid or uninitialized LinkPreview scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    linkpreview_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede URL construction and the constructor skip. */
        if (key.len != 32)
            rc = linkpreview_fail(&owned_error, "invalid LinkPreview capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = linkpreview_fail(&owned_error, "cannot create LinkPreview result");
        else if (verify) {
            int verdict = linkpreview_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict < 0) rc = -1;
            else keep = verdict == 0;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = linkpreview_fail(&owned_error, "cannot append LinkPreview result");
        br_result_clear(&result);
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    linkpreview_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const linkpreview_keywords[] = {"linkpreview"};
static br_detector linkpreview_detector = {
    .type = 438, .version = 0, .name = "LinkPreview", .custom_name = "",
    .description = "LinkPreview is a service that provides information about a web page when given a URL. LinkPreview API keys can be used to access this service and retrieve metadata about web pages.",
    .keywords = linkpreview_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = linkpreview_scan,
};

int br_linkpreview_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return linkpreview_fail(error, "invalid LinkPreview detector output");
    *out = NULL;
    if (!linkpreview_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(linkpreview_keywords, 1,
                                      "\\b([a-zA-Z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        linkpreview_detector.state = regex;
    }
    *out = &linkpreview_detector;
    return 0;
}
