/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lessannoyingcrm/lessannoyingcrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int lacrm_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Go fmt of strings.Split(key, "-"): '[' + elements joined by one space + ']'.
 * Empty elements remain. This is not a hyphen join and is not percent-encoded.
 * The return is the byte count, excluding the terminator. Negative means the
 * buffer cannot hold the value; a positive count is not a status code. */
static int format_user_code(char *out, size_t cap, br_slice key)
{
    if (!out || cap < 3) return -1;
    size_t at = 0;
    out[at++] = '[';
    bool first = true;
    size_t start = 0;
    for (size_t i = 0; i <= key.len; ++i) {
        if (i < key.len && key.data[i] != '-') continue;
        size_t n = i - start;
        size_t need = n + (first ? 0u : 1u);
        if (need > cap - at - 2) return -1;
        if (!first) out[at++] = ' ';
        if (n) {
            memcpy(out + at, key.data + start, n);
            at += n;
        }
        first = false;
        start = i + 1;
    }
    out[at++] = ']';
    out[at] = '\0';
    return (int)at;
}

/* Successful Do closes are scan-deferred. The stack header array dies at send
 * return, so only the response and the original URL allocation are kept. */
typedef struct lacrm_pending lacrm_pending;
struct lacrm_pending {
    lacrm_pending *next;
    br_http_response response;
    char *url;
};

static int lacrm_retain(lacrm_pending **pending, const br_http_response *response, char *url)
{
    lacrm_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->url = url;
    *pending = item;
    return 0;
}

/* Last success first. The original URL is freed only after its own release. */
static void lacrm_release_held(const br_scan_ctx *ctx, lacrm_pending *pending)
{
    while (pending) {
        lacrm_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->url);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. UserCode and the complete URL are owned before the
 * nil-context drop. A nil context frees that URL and drops the candidate. */
static int lacrm_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                        bool *keep, lacrm_pending **pending, char **error)
{
    static const char prefix[] = "https://api.lessannoyingcrm.com?UserCode=";
    static const char mid[] = "&APIToken=";
    static const char suffix[] = "&Function=GetUserInfo";
    char usercode[64];
    int count = format_user_code(usercode, sizeof(usercode), key);
    if (count < 0) return lacrm_fail(error, "cannot format LessAnnoyingCRM UserCode");
    size_t ulen = (size_t)count;
    size_t need = sizeof(prefix) - 1 + ulen + sizeof(mid) - 1 + key.len + sizeof(suffix);
    char *url = malloc(need);
    if (!url) return lacrm_fail(error, "cannot format LessAnnoyingCRM URL");
    size_t at = 0;
    memcpy(url + at, prefix, sizeof(prefix) - 1);
    at += sizeof(prefix) - 1;
    memcpy(url + at, usercode, ulen);
    at += ulen;
    memcpy(url + at, mid, sizeof(mid) - 1);
    at += sizeof(mid) - 1;
    memcpy(url + at, key.data, key.len);
    at += key.len;
    memcpy(url + at, suffix, sizeof(suffix));
    if (!ctx) {
        free(url);
        *keep = false;
        return 0;
    }
    const br_header headers[] = {{"Accept", "application/vnd.lessannoyingcrm+json; version=3"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* Source never reads the body, so body_error cannot suppress a 2xx or drop
     * the finding. The whole mixed setup/Do domain stays unverified. Never set
     * a verification error. Do not retain the stack header array. */
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(url);
        return 0;
    }
    if (lacrm_retain(pending, &response, url) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return lacrm_fail(error, "cannot retain LessAnnoyingCRM response for release");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    return 0;
}

static int lacrm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lacrm_fail(error, "invalid or uninitialized LessAnnoyingCRM scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lacrm_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Keep every occurrence. Finding resources
         * precede URL formatting and the constructor skip. */
        if (key.len != 57)
            rc = lacrm_fail(&owned_error, "invalid LessAnnoyingCRM capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lacrm_fail(&owned_error, "cannot create LessAnnoyingCRM result");
        else if (verify && lacrm_verify(ctx, key, &result, &keep, &pending, &owned_error) != 0)
            rc = -1;
        else if (verify && !keep) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = lacrm_fail(&owned_error, "cannot append LessAnnoyingCRM result");
        br_result_clear(&result);
    }
    /* Successful responses close after append, last success first. Formatter,
     * retention, finding, and push failures drain the same list once, with
     * each original URL still intact, then roll back only this invocation. */
    lacrm_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

/* Engine prefilter keyword. The regex prefix is the separate literal "less". */
static const char *const lacrm_keywords[] = {"lessannoyingcrm"};
static const char *const lacrm_prefix[] = {"less"};
static br_detector lacrm_detector = {
    .type = 267, .version = 0, .name = "LessAnnoyingCRM", .custom_name = "",
    .description = "Less Annoying CRM is a customer relationship management system. The API token can be used to access and manage customer data.",
    .keywords = lacrm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lacrm_scan,
};

int br_lessannoyingcrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lacrm_fail(error, "invalid LessAnnoyingCRM detector output");
    *out = NULL;
    if (!lacrm_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(lacrm_prefix, 1, "\\b([a-zA-Z0-9-]{57})\\b", &regex, error) != 0)
            return -1;
        lacrm_detector.state = regex;
    }
    *out = &lacrm_detector;
    return 0;
}
