/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/reachmail/reachmail.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { REACH_KEEP = 0, REACH_DROP = 1, REACH_FATAL = -1 };

static int reach_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return REACH_FATAL;
}

static int reach_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 64) return REACH_FATAL;
    if (!ctx) return REACH_DROP;
    char authorization[7 + 64 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 64);
    authorization[71] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://services.reachmail.net/administration/users/current",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return REACH_KEEP;
}

static int reach_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return reach_fail(error, "invalid or uninitialized Reachmail scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        int outcome = REACH_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            outcome = reach_fail(&owned_error, "cannot create Reachmail result");
        else if (verify)
            outcome = reach_verify(ctx, key, &result);
        if (outcome == REACH_FATAL) rc = -1;
        if (outcome == REACH_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = reach_fail(&owned_error, "cannot append Reachmail result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const reach_keywords[] = {"reachmail"};
static br_detector reach_detector = {
    .type = 814, .version = 0, .name = "Reachmail", .custom_name = "",
    .description = "Reachmail is an email marketing service. Reachmail API keys can be used to access and manage email marketing campaigns and user data.",
    .keywords = reach_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = reach_scan,
};

int br_reachmail_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return reach_fail(error, "invalid Reachmail detector output");
    *out = NULL;
    if (br_key_pattern_init(&reach_detector, "\\b([a-zA-Z0-9-_]{64})\\b", error) != 0)
        return -1;
    *out = &reach_detector;
    return 0;
}
