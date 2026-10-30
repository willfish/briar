/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/percy/percy.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int percy_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int percy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return percy_fail(error, "invalid or uninitialized Percy scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* The capture is the 64-byte value after the literal PERCY_TOKEN=. */
        if (key.len != 64 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = percy_fail(&owned_error, "cannot create Percy result");
        if (rc == 0 && verify) {
            /* Fixed-URL constructor failure drops before either header. */
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            char authorization[sizeof("Token ") + 64];
            memcpy(authorization, "Token ", 6);
            memcpy(authorization + 6, key.data, 64);
            authorization[70] = '\0';
            const br_header headers[] = {
                {"Accept", "application/vnd.percy+json; version=3"},
                {"Authorization", authorization},
            };
            const br_http_request request = {
                .method = "GET", .url = "https://percy.io/api/v1/projects",
                .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
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
            rc = percy_fail(&owned_error, "cannot append Percy result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const percy_keywords[] = {"percy"};
static br_detector percy_detector = {
    .type = 912, .version = 0, .name = "Percy", .custom_name = "",
    .description = "Percy is a visual testing and review platform. Percy tokens can be used to access and manage visual testing projects.",
    .keywords = percy_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = percy_scan,
};

int br_percy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return percy_fail(error, "invalid Percy detector output");
    *out = NULL;
    if (br_key_pattern_init(&percy_detector, "\\bPERCY_TOKEN=([0-9Aa-f]{64})\\b", error) != 0) return -1;
    *out = &percy_detector;
    return 0;
}
