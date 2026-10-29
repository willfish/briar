/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/livestorm/livestorm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

enum { livestorm_raw_len = 243, livestorm_capture_len = 244 };

static int livestorm_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The capture requires one trailing space, CR, or LF. This alphabet cannot
 * contain other TrimSpace runes, so dropping that byte is strings.TrimSpace. */
static bool trim_capture(br_slice *key)
{
    if (!key->data || key->len != livestorm_capture_len) return false;
    unsigned char last = key->data[key->len - 1];
    if (last != ' ' && last != '\r' && last != '\n') return false;
    --key->len;
    return true;
}

/* Successful Do closes are scan-deferred. A stack Authorization cannot survive
 * that release, so the original allocation stays with the response. The stack
 * header array is not retained. */
typedef struct livestorm_pending livestorm_pending;
struct livestorm_pending {
    livestorm_pending *next;
    br_http_response response;
    char *authorization;
};

static int livestorm_retain(livestorm_pending **pending, const br_http_response *response,
                            char *authorization)
{
    livestorm_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->authorization = authorization;
    *pending = item;
    return 0;
}

static void livestorm_release_held(const br_scan_ctx *ctx, livestorm_pending *pending)
{
    while (pending) {
        livestorm_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. Nil context drops before Authorization allocation.
 * 1 drops this occurrence. 0 publishes it. -1 is fatal. There is no setter. */
static int livestorm_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            livestorm_pending **pending, char **error)
{
    if (!ctx) return 1;
    char *authorization = malloc(key.len + 1);
    if (!authorization) return livestorm_fail(error, "cannot allocate Livestorm authorization");
    memcpy(authorization, key.data, key.len);
    authorization[key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.livestorm.co/v1/ping",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    /* Setup and Do errors stay unverified. Do not invent a verification cause. */
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return 0;
    }
    if (livestorm_retain(pending, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return livestorm_fail(error, "cannot retain Livestorm response for release");
    }
    /* Source never reads the body, so body_error cannot suppress a 2xx or drop it. */
    result->verified = response.status >= 200 && response.status < 300;
    return 0;
}

static int livestorm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return livestorm_fail(error, "invalid or uninitialized Livestorm scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    livestorm_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* Keep every occurrence. Finding resources use the trimmed token and
         * precede the constructor skip and any Authorization allocation. */
        if (!trim_capture(&key))
            rc = livestorm_fail(&owned_error, "invalid Livestorm capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = livestorm_fail(&owned_error, "cannot create Livestorm result");
        else if (verify) {
            int verdict = livestorm_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict < 0) rc = -1;
            else keep = verdict == 0;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = livestorm_fail(&owned_error, "cannot append Livestorm result");
        br_result_clear(&result);
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    livestorm_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const livestorm_keywords[] = {"livestorm"};
/* Source spelling. Do not rewrite [0-9A-Z-a-z] and do not add a trailing \b. */
static const char livestorm_capture[] =
    "\\b(eyJhbGciOiJIUzI1NiJ9\\.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi"
    "[0-9A-Z-a-z]{134}\\.[0-9A-Za-z\\-\\_]{43}[ \\r\\n]{1})";
static br_detector livestorm_detector = {
    .type = 735, .version = 0, .name = "Livestorm", .custom_name = "",
    .description = "Livestorm is a video communication platform for webinars, meetings, and virtual events. Livestorm API keys can be used to interact with Livestorm services programmatically.",
    .keywords = livestorm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = livestorm_scan,
};

int br_livestorm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return livestorm_fail(error, "invalid Livestorm detector output");
    *out = NULL;
    if (!livestorm_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(livestorm_keywords, 1, livestorm_capture, &regex, error) != 0)
            return -1;
        livestorm_detector.state = regex;
    }
    *out = &livestorm_detector;
    return 0;
}
