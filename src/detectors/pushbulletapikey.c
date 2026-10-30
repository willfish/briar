/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pushbulletapikey/pushbulletapikey.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int pushbulletapikey_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pushbulletapikey_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pushbulletapikey_fail(error, "invalid or uninitialized PushBulletApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 34 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pushbulletapikey_fail(&owned_error, "cannot create PushBulletApiKey result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.pushbullet.com/v2/users/me";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const char *h0 = (const char *)key.data;
            const br_header headers[] = {{"Access-Token", h0}};
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
            rc = pushbulletapikey_fail(&owned_error, "cannot append PushBulletApiKey result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pushbulletapikey_keywords[] = {"pushbullet"};
static br_detector pushbulletapikey_detector = {
    .type = 124, .version = 0, .name = "PushBulletApiKey", .custom_name = "",
    .description = "Pushbullet is a service that allows you to send notifications between your devices. Pushbullet API keys can be used to interact with the Pushbullet API to send and receive notifications.",
    .keywords = pushbulletapikey_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pushbulletapikey_scan,
};

int br_pushbulletapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pushbulletapikey_fail(error, "invalid PushBulletApiKey detector output");
    *out = NULL;
    if (br_key_pattern_init(&pushbulletapikey_detector, "\\b([A-Za-z0-9_\\.]{34})\\b", error) != 0) return -1;
    *out = &pushbulletapikey_detector;
    return 0;
}
