/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/yandex/yandex.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int yandex_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int yandex_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return yandex_fail(error, "invalid or uninitialized Yandex scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 83 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = yandex_fail(&owned_error, "cannot create Yandex result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://dictionary.yandex.net/api/v1/dicservice.json/getLangs?key=";
            char url[sizeof(prefix) + 83];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 83);
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
            rc = yandex_fail(&owned_error, "cannot append Yandex result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const yandex_keywords[] = {"yandex"};
static br_detector yandex_detector = {
    .type = 279, .version = 0, .name = "Yandex", .custom_name = "",
    .description = "Yandex is a technology company that builds intelligent products and services powered by machine learning. Yandex API keys can be used to access and interact with various Yandex services.",
    .keywords = yandex_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = yandex_scan,
};

int br_yandex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return yandex_fail(error, "invalid Yandex detector output");
    *out = NULL;
    if (br_key_pattern_init(&yandex_detector, "\\b([a-z0-9A-Z.]{83})\\b", error) != 0) return -1;
    *out = &yandex_detector;
    return 0;
}
