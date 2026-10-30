/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/todoist/todoist.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { TODO_ABORT = -1, TODO_KEEP = 0, TODO_SKIP = 1 } todo_outcome;

static int todo_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static todo_outcome todo_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return TODO_SKIP;
    char authorization[7 + 40 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.todoist.com/api/v1/projects",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return TODO_KEEP;
}

static int todo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return todo_fail(error, "invalid or uninitialized Todoist scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Ordered duplicates stay. TrimSpace cannot change this lowercase class. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        todo_outcome outcome = TODO_KEEP;
        if (key.len != 40) {
            todo_fail(&owned_error, "invalid Todoist capture");
            outcome = TODO_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            todo_fail(&owned_error, "cannot create Todoist result");
            outcome = TODO_ABORT;
        } else if (verify) {
            outcome = todo_verify(ctx, key, &result);
        }
        if (outcome == TODO_KEEP && br_results_push(out, &result) != 0) {
            todo_fail(&owned_error, "cannot append Todoist result");
            outcome = TODO_ABORT;
        }
        br_result_clear(&result);
        if (outcome == TODO_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const todo_keywords[] = {"todoist"};
static br_detector todo_detector = {
    .type = 339, .version = 0, .name = "Todoist", .custom_name = "",
    .description = "Todoist is a task management application. Todoist API keys can be used to access and manage tasks and projects within a user's account.",
    .keywords = todo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = todo_scan,
};

int br_todoist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return todo_fail(error, "invalid Todoist detector output");
    *out = NULL;
    if (br_key_pattern_init(&todo_detector, "\\b([0-9a-z]{40})\\b", error) != 0)
        return -1;
    *out = &todo_detector;
    return 0;
}
