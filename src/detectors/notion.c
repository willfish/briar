/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/notion/notion.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int notion_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. A stack token cannot survive that
 * release, so the original Authorization allocation stays with the response.
 * The stack header array is not retained. */
typedef struct notion_pending notion_pending;
struct notion_pending {
    notion_pending *next;
    br_http_response response;
    char *authorization;
};

static int notion_retain(notion_pending **pending, const br_http_response *response,
                         char *authorization)
{
    notion_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->authorization = authorization;
    *pending = item;
    return 0;
}

static void notion_release_held(const br_scan_ctx *ctx, notion_pending *pending)
{
    while (pending) {
        notion_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. A nil context drops before Authorization allocation.
 * 1 drops this occurrence. 0 publishes it. Any other status, including +1, is
 * fatal. Body and read errors do not affect the status verdict. */
static int notion_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                         notion_pending **pending, char **error)
{
    if (!ctx) return 1;
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) return notion_fail(error, "cannot allocate Notion authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    /* The header array dies at send return. Do not retain it. */
    const br_header headers[] = {
        {"Notion-Version", "2022-06-28"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.notion.com/v1/users",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    if (send_rc != 0) {
        /* Release once before the setter. A setter failure must not skip it
         * or release again. Pass the reached transport error; NULL is a no-op. */
        br_http_release(ctx, &response);
        free(authorization);
        int stored = br_result_set_verification_error(result, send_error, &key, 1);
        free(send_error);
        if (stored != 0) return notion_fail(error, "cannot record Notion verification error");
        return 0;
    }
    free(send_error);
    if (notion_retain(pending, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return notion_fail(error, "cannot retain Notion response for release");
    }
    /* 200-299 or exactly 403. 401 and every other status stay unverified.
     * No setter after a successful send. */
    result->verified = (response.status >= 200 && response.status < 300) || response.status == 403;
    return 0;
}

static int notion_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return notion_fail(error, "invalid or uninitialized Notion scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    notion_pending *pending = NULL;
    char *owned_error = NULL;
    /* The keyword is an engine hint only. TrimSpace is a no-op. Keep every
     * duplicate. Finding resources precede the nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        if (key.len != 50)
            rc = notion_fail(&owned_error, "invalid Notion capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = notion_fail(&owned_error, "cannot create Notion result");
        else if (verify) {
            int verdict = notion_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict == 1) keep = false;
            else if (verdict != 0) rc = -1;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = notion_fail(&owned_error, "cannot append Notion result");
        br_result_clear(&result);
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    notion_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const notion_keywords[] = {"notion"};
static br_detector notion_detector = {
    .type = 134, .version = 0, .name = "Notion", .custom_name = "",
    .description = "Notion is a productivity tool that provides an all-in-one workspace for note-taking, project management, and collaboration. Notion API keys can be used to access and modify data within a user's Notion workspace.",
    .keywords = notion_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = notion_scan,
};

int br_notion_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return notion_fail(error, "invalid Notion detector output");
    *out = NULL;
    if (!notion_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(secret_[A-Za-z0-9]{43})\\b", &regex, error) != 0)
            return -1;
        notion_detector.state = regex;
    }
    *out = &notion_detector;
    return 0;
}
