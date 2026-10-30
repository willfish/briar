/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/postageapp/postageapp.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int postageapp_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int postageapp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return postageapp_fail(error, "invalid or uninitialized PostageApp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = postageapp_fail(&owned_error, "cannot create PostageApp result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://api.postageapp.com/v.1.0/get_account_info.json?api_key=";
            char url[sizeof(prefix) + 32];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 32);
            url[sizeof(url) - 1] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {{"Content-Transfer-Encoding", "application/json"}};
            const br_http_request request = {
                .method = "POST", .url = url, .headers = headers, .nheaders = 1,
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
            rc = postageapp_fail(&owned_error, "cannot append PostageApp result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const postageapp_keywords[] = {"postageapp"};
static br_detector postageapp_detector = {
    .type = 575, .version = 0, .name = "PostageApp", .custom_name = "",
    .description = "PostageApp is a service for sending emails via their API. The API keys can be used to send emails and access account information.",
    .keywords = postageapp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = postageapp_scan,
};

int br_postageapp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return postageapp_fail(error, "invalid PostageApp detector output");
    *out = NULL;
    if (br_key_pattern_init(&postageapp_detector, "\\b([0-9A-Za-z]{32})\\b", error) != 0) return -1;
    *out = &postageapp_detector;
    return 0;
}
