/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pipedrive/pipedrive.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int pipedrive_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pipedrive_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pipedrive_fail(error, "invalid or uninitialized Pipedrive scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pipedrive_fail(&owned_error, "cannot create Pipedrive result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://hooman.pipedrive.com/api/v1/users?api_token=";
            char url[sizeof(prefix) + 40];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 40);
            url[sizeof(url) - 1] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            char authorization[sizeof("Bearer ") + 40];
            memcpy(authorization, "Bearer ", 7);
            memcpy(authorization + 7, key.data, 40);
            authorization[47] = '\0';
            const br_header headers[] = {{"Authorization", authorization}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 1,
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
            rc = pipedrive_fail(&owned_error, "cannot append Pipedrive result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pipedrive_keywords[] = {"pipedrive"};
static br_detector pipedrive_detector = {
    .type = 159, .version = 0, .name = "Pipedrive", .custom_name = "",
    .description = "Pipedrive is a sales-focused customer relationship management (CRM) tool. Pipedrive API tokens can be used to access and manipulate CRM data.",
    .keywords = pipedrive_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pipedrive_scan,
};

int br_pipedrive_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pipedrive_fail(error, "invalid Pipedrive detector output");
    *out = NULL;
    if (br_key_pattern_init(&pipedrive_detector, "\\b([a-zA-Z0-9]{40})\\b", error) != 0) return -1;
    *out = &pipedrive_detector;
    return 0;
}
