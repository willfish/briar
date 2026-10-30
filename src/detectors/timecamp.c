/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/timecamp/timecamp.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int timecamp_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int timecamp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return timecamp_fail(error, "invalid or uninitialized TimeCamp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 26 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = timecamp_fail(&owned_error, "cannot create TimeCamp result");
        if (rc == 0 && verify) {
            static const char url[] = "https://app.timecamp.com/third_party/api/user?format=json";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            static const char h0[] = "application/vnd.timecamp+json; version=3";
            const char *h1 = (const char *)key.data;
            const br_header headers[] = {{"Accept", h0}, {"Authorization", h1}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = timecamp_fail(&owned_error, "cannot append TimeCamp result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const timecamp_keywords[] = {"timecamp"};
static br_detector timecamp_detector = {
    .type = 778, .version = 0, .name = "TimeCamp", .custom_name = "",
    .description = "TimeCamp is a time tracking software for teams and freelancers. TimeCamp API keys can be used to access and modify time tracking data.",
    .keywords = timecamp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = timecamp_scan,
};

int br_timecamp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return timecamp_fail(error, "invalid TimeCamp detector output");
    *out = NULL;
    if (br_key_pattern_init(&timecamp_detector, "\\b([0-9a-z]{26})\\b", error) != 0) return -1;
    *out = &timecamp_detector;
    return 0;
}
