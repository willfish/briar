/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sportsmonk/sportsmonk.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int sportsmonk_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sportsmonk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sportsmonk_fail(error, "invalid or uninitialized Sportsmonk scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 60 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = sportsmonk_fail(&owned_error, "cannot create Sportsmonk result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://soccer.sportmonks.com/api/v2.0/leagues?api_token=";
            char url[sizeof(prefix) + 60];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 60);
            url[sizeof(url) - 1] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = sportsmonk_fail(&owned_error, "cannot append Sportsmonk result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sportsmonk_keywords[] = {"sportsmonk"};
static br_detector sportsmonk_detector = {
    .type = 470, .version = 0, .name = "Sportsmonk", .custom_name = "",
    .description = "Sportsmonk is a video game database and discovery service. Sportsmonk API keys can be used to access game data and related services.",
    .keywords = sportsmonk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sportsmonk_scan,
};

int br_sportsmonk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sportsmonk_fail(error, "invalid Sportsmonk detector output");
    *out = NULL;
    if (br_key_pattern_init(&sportsmonk_detector, "\\b([0-9a-zA-Z]{60})\\b", error) != 0) return -1;
    *out = &sportsmonk_detector;
    return 0;
}
