/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pandascore/pandascore.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

enum { pandascore_key_len = 51 };

static int pandascore_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The capture has at most one leading space, CR, or LF and requires one
 * trailing byte from that set. The class cannot contain other TrimSpace
 * runes, so dropping only those captured bytes is strings.TrimSpace. */
static bool trim_capture(br_slice *key)
{
    if (!key->data || (key->len != 52 && key->len != 53)) return false;
    unsigned char last = key->data[key->len - 1];
    if (last != ' ' && last != '\r' && last != '\n') return false;
    size_t start = 0;
    if (key->len == 53) {
        unsigned char first = key->data[0];
        if (first != ' ' && first != '\r' && first != '\n') return false;
        start = 1;
    }
    key->data += start;
    key->len = pandascore_key_len;
    return true;
}

/* Successful Do closes are scan-deferred. A stack Authorization cannot survive
 * that release, so the original allocation stays with the response. The stack
 * header array is not retained. */
typedef struct pandascore_pending pandascore_pending;
struct pandascore_pending {
    pandascore_pending *next;
    br_http_response response;
    char *authorization;
};

static int pandascore_retain(pandascore_pending **pending, const br_http_response *response,
                             char *authorization)
{
    pandascore_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->authorization = authorization;
    *pending = item;
    return 0;
}

static void pandascore_release_held(const br_scan_ctx *ctx, pandascore_pending *pending)
{
    while (pending) {
        pandascore_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. Nil context drops before Authorization allocation.
 * 1 drops this occurrence. 0 publishes it. -1 is fatal. There is no setter. */
static int pandascore_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             pandascore_pending **pending, char **error)
{
    if (!ctx) return 1;
    char *authorization = malloc(sizeof("Bearer ") + key.len);
    if (!authorization) return pandascore_fail(error, "cannot allocate PandaScore authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.pandascore.co/videogames",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return 0;
    }
    if (pandascore_retain(pending, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return pandascore_fail(error, "cannot retain PandaScore response for release");
    }
    /* Source never reads the body. A reached non-2xx is explicitly unverified. */
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else
        result->verified = false;
    return 0;
}

static int pandascore_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pandascore_fail(error, "invalid or uninitialized PandaScore scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    pandascore_pending *pending = NULL;
    char *owned_error = NULL;
    /* Keep every duplicate. Finding resources use the trimmed token and precede
     * the nil-context drop and any Authorization allocation. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        if (!trim_capture(&key))
            rc = pandascore_fail(&owned_error, "invalid PandaScore capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pandascore_fail(&owned_error, "cannot create PandaScore result");
        else if (verify) {
            int verdict = pandascore_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict < 0) rc = -1;
            else keep = verdict == 0;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = pandascore_fail(&owned_error, "cannot append PandaScore result");
        br_result_clear(&result);
    }
    /* Successful responses close after publication, last success first. Fatal
     * paths drain the same list once, then roll back only this invocation. */
    pandascore_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pandascore_keywords[] = {"pandascore"};
/* Source spelling. Do not add a word boundary and do not rewrite the class. */
static const char pandascore_capture[] = "([ \\r\\n]{0,1}[0-9A-Za-z\\-\\_]{51}[ \\r\\n]{1})";
static br_detector pandascore_detector = {
    .type = 731, .version = 0, .name = "PandaScore", .custom_name = "",
    .description = "PandaScore is an esports data provider offering a wide range of statistics and live data for various video games. PandaScore API keys can be used to access and retrieve this data.",
    .keywords = pandascore_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pandascore_scan,
};

int br_pandascore_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pandascore_fail(error, "invalid PandaScore detector output");
    *out = NULL;
    if (!pandascore_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(pandascore_keywords, 1, pandascore_capture, &regex, error) != 0)
            return -1;
        pandascore_detector.state = regex;
    }
    *out = &pandascore_detector;
    return 0;
}
