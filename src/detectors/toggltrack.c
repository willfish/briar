/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/toggltrack/toggltrack.go.
 * The defaults constructor is commented out; the scanner remains reachable. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { TOGGL_KEEP = 0, TOGGL_DROP = 1, TOGGL_FATAL = -1 };

static int toggl_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return TOGGL_FATAL;
}

static int toggl_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char suffix[] = "api_token";
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){(const unsigned char *)suffix, sizeof(suffix) - 1},
                           &authorization, error) != 0)
        return TOGGL_FATAL;
    unsigned char dedup[4 + 32];
    memcpy(dedup, "290:", 4);
    memcpy(dedup + 4, key.data, 32);
    /* Basic value exists before the nil-context constructor skip. */
    int outcome = ctx ? TOGGL_KEEP : TOGGL_DROP;
    if (outcome == TOGGL_KEEP) {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.track.toggl.com/api/v8/me",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type, .dedup_key = {dedup, sizeof(dedup)},
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) == 0)
            result->verified = response.status >= 200 && response.status < 300;
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(authorization);
    return outcome;
}

static int toggl_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return toggl_fail(error, "invalid or uninitialized TogglTrack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        int outcome = TOGGL_KEEP;
        if (key.len != 32) outcome = toggl_fail(&owned_error, "invalid TogglTrack key");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            outcome = toggl_fail(&owned_error, "cannot create TogglTrack result");
        else if (verify)
            outcome = toggl_verify(ctx, key, &result, &owned_error);
        if (outcome == TOGGL_FATAL) rc = -1;
        if (outcome == TOGGL_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = toggl_fail(&owned_error, "cannot append TogglTrack result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const toggl_keywords[] = {"toggl"};
static br_detector toggl_detector = {
    .type = 290, .version = 0, .name = "TogglTrack", .custom_name = "",
    .description = "TogglTrack is a time tracking tool. TogglTrack API keys can be used to access and manage time tracking data.",
    .keywords = toggl_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = toggl_scan,
};

int br_toggltrack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return toggl_fail(error, "invalid TogglTrack detector output");
    *out = NULL;
    if (br_key_pattern_init(&toggl_detector, "\\b([0-9Aa-z]{32})\\b", error) != 0) return -1;
    *out = &toggl_detector;
    return 0;
}
