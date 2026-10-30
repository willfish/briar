/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/youtubeapikey/youtubeapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } yt_patterns;
typedef enum { YT_ABORT = -1, YT_KEEP = 0, YT_DROP = 1 } yt_outcome;

static int yt_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static yt_outcome yt_verify(const br_scan_ctx *ctx, const char *key, const char *id,
                            br_result *result, char **error)
{
    char url[160];
    int n = snprintf(url, sizeof(url),
                     "https://www.googleapis.com/youtube/v3/channelSections?key=%s&channelId=%s",
                     key, id);
    if (n < 0 || (size_t)n >= sizeof(url))
        return yt_fail(error, "cannot format YoutubeApiKey URL"), YT_ABORT;
    if (!ctx) return YT_DROP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return YT_KEEP;
}

static int yt_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return yt_fail(error, "invalid or uninitialized YoutubeApiKey scan");
    const yt_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            yt_outcome outcome = YT_KEEP;
            /* The channel id is a verification input only. Raw and secret parts are the key. */
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = yt_fail(&owned_error, "cannot create YoutubeApiKey result");
            else if (verify)
                outcome = yt_verify(ctx, keys.items[k], ids.items[i], &result, &owned_error);
            if (rc == 0 && outcome == YT_ABORT) rc = -1;
            if (rc == 0 && outcome == YT_KEEP && br_results_push(out, &result) != 0)
                rc = yt_fail(&owned_error, "cannot append YoutubeApiKey result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const yt_keywords[] = {"youtube"};
static yt_patterns yt_state;
static br_detector yt_detector = {
    .type = 46, .version = 0, .name = "YoutubeApiKey", .custom_name = "",
    .description = "YouTube API Keys allow access to various functionalities of the YouTube Data API, enabling operations such as retrieving video details and managing playlists.",
    .keywords = yt_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = yt_scan, .state = &yt_state,
};

int br_youtubeapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return yt_fail(error, "invalid YoutubeApiKey detector output");
    *out = NULL;
    if (!yt_state.key &&
        br_regex_compile_prefixed(yt_keywords, 1, "\\b([a-zA-Z-0-9_]{39})\\b", &yt_state.key, error) != 0)
        return -1;
    if (!yt_state.id &&
        br_regex_compile_prefixed(yt_keywords, 1, "\\b([a-zA-Z-0-9]{24})\\b", &yt_state.id, error) != 0)
        return -1;
    *out = &yt_detector;
    return 0;
}
