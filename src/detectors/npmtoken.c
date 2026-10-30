/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/npmtoken and npmtokenv2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef enum { NPM_ABORT = -1, NPM_KEEP = 0, NPM_DROP = 1 } npm_outcome;
typedef struct {
    br_http_response response;
    char *authorization;
} npm_held;
typedef struct {
    npm_held *items;
    size_t len, cap;
} npm_pending;

static const char npm_url[] = "https://registry.npmjs.org/-/whoami";
static const char npm_guide[] = "https://howtorotate.com/docs/tutorials/npm/";

static int npm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int npm_metadata(br_result *result, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return npm_fail(error, "cannot create NpmToken metadata");
    br_json *guide = json_object_new_string(npm_guide);
    if (!guide) return npm_fail(error, "cannot create NpmToken metadata");
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return npm_fail(error, "cannot create NpmToken metadata");
    }
    return 0;
}

static void npm_drain(const br_scan_ctx *ctx, npm_pending *pending)
{
    while (pending->len) {
        npm_held *item = &pending->items[--pending->len];
        br_http_release(ctx, &item->response);
        free(item->authorization);
    }
    free(pending->items);
    *pending = (npm_pending){0};
}

static int npm_hold(npm_pending *pending, const br_http_response *response,
                    char *authorization, char **error)
{
    if (pending->len == pending->cap) {
        size_t cap = pending->cap ? pending->cap * 2 : 2;
        if (cap < pending->cap || cap > SIZE_MAX / sizeof(*pending->items))
            return npm_fail(error, "cannot retain NpmToken response");
        npm_held *items = realloc(pending->items, cap * sizeof(*items));
        if (!items) return npm_fail(error, "cannot retain NpmToken response");
        pending->items = items;
        pending->cap = cap;
    }
    pending->items[pending->len++] = (npm_held){*response, authorization};
    return 0;
}

static npm_outcome npm_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              npm_pending *pending, char **error)
{
    /* NewRequestWithContext fails before Header.Add. A nil context is not a send.
     * A zeroed context pointer is not nil and continues to Do. */
    if (!ctx) return NPM_DROP;
    char *authorization = NULL;
    if (key.len > SIZE_MAX - 8 || !(authorization = malloc(7 + key.len + 1))) {
        npm_fail(error, "cannot allocate NpmToken authorization");
        return NPM_ABORT;
    }
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = npm_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* A failed Do or preparation releases immediately. The synthesized
     * User-Agent array dies when send returns; do not retain it. */
    if (sent != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return NPM_KEEP;
    }
    /* Successful Close waits until this scan returns. URL, Authorization, and
     * the key remain the originals. Body and read errors are ignored. */
    result->verified = response.status >= 200 && response.status < 300;
    if (npm_hold(pending, &response, authorization, error) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return NPM_ABORT;
    }
    return NPM_KEEP;
}

static int npm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return npm_fail(error, "invalid or uninitialized NpmToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    npm_pending pending = {0};
    char *owned_error = NULL;
    /* Duplicates remain. v1's prefix is in the compiled pattern; v2 has none. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        npm_outcome outcome = NPM_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = npm_fail(&owned_error, "cannot create NpmToken result");
        else if (npm_metadata(&result, &owned_error) != 0)
            rc = -1;
        else if (verify)
            outcome = npm_verify(ctx, key, &result, &pending, &owned_error);
        if (rc == 0 && outcome == NPM_ABORT) rc = -1;
        if (rc == 0 && outcome == NPM_KEEP && br_results_push(out, &result) != 0)
            rc = npm_fail(&owned_error, "cannot append NpmToken result");
        br_result_clear(&result);
    }
    /* Scanner-return LIFO, after publication and on a later fatal path.
     * Captures and the static URL are still alive for this drain. */
    npm_drain(ctx, &pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const npm_v1_keywords[] = {"npm"};
static br_detector npm_v1 = {
    .type = 49, .version = 1, .name = "NpmToken", .custom_name = "",
    .description = "NPM tokens are used to authenticate and publish packages to the npm registry.",
    .keywords = npm_v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = npm_scan,
};

static const char *const npm_v2_keywords[] = {"npm_"};
static br_regex *npm_v2_regex;
static br_detector npm_v2 = {
    .type = 49, .version = 2, .name = "NpmToken", .custom_name = "",
    .description = "NPM tokens are used to authenticate and publish packages to the NPM registry.",
    .keywords = npm_v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = npm_scan,
};

int br_npmtoken_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return npm_fail(error, "invalid NpmToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&npm_v1,
            "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            error) != 0) return -1;
    *out = &npm_v1;
    return 0;
}

int br_npmtoken_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return npm_fail(error, "invalid NpmToken detector output");
    *out = NULL;
    if (!npm_v2_regex && br_regex_compile("(npm_[0-9a-zA-Z]{36})", &npm_v2_regex, error) != 0)
        return -1;
    npm_v2.state = npm_v2_regex;
    *out = &npm_v2;
    return 0;
}
