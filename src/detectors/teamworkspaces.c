/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/teamworkspaces/teamworkspaces.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static char *trim_copy(const char *text, size_t *len, char **error)
{
    size_t start = 0, end = *len;
    while (start < end && strchr(" \t\n\v\f\r", text[start])) ++start;
    while (end > start && strchr(" \t\n\v\f\r", text[end - 1])) --end;
    char *copy = malloc(end - start + 1);
    if (!copy) {
        fail(error, "cannot trim TeamworkSpaces token");
        return NULL;
    }
    memcpy(copy, text + start, end - start);
    copy[end - start] = '\0';
    *len = end - start;
    return copy;
}

static int verify_teamwork(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return 1;
    char authorization[128];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization))
        return fail(error, "cannot format TeamworkSpaces authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://example.teamwork.com/spaces/api/v1/users.json",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_teamwork(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TeamworkSpaces scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        size_t len = keys.lengths[i];
        char *trimmed = trim_copy(keys.items[i], &len, &owned_error);
        br_result result = {0};
        int outcome = trimmed ? 0 : -1;
        if (!outcome && br_finding_key_bytes(&result, detector->type,
                                             (br_slice){(const unsigned char *)trimmed, len}, "key") != 0) {
            fail(&owned_error, "cannot create TeamworkSpaces result");
            outcome = -1;
        } else if (!outcome && verify)
            outcome = verify_teamwork(ctx, trimmed, &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append TeamworkSpaces result");
            outcome = -1;
        }
        br_result_clear(&result);
        free(trimmed);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"teamwork", "teamworkspaces"};
static br_detector teamwork = {
    .type = 630, .version = 0, .name = "TeamworkSpaces", .custom_name = "",
    .description = "TeamworkSpaces is a collaboration tool for teams to share documents and information. The detected key can be used to access and modify spaces and documents within TeamworkSpaces.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_teamwork,
};

int br_teamworkspaces_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TeamworkSpaces detector output");
    *out = NULL;
    if (!teamwork.state &&
        br_key_pattern_init(&teamwork, "\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n]{1})", error) != 0)
        return -1;
    *out = &teamwork;
    return 0;
}
