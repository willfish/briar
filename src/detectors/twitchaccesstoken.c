/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twitchaccesstoken/twitchaccesstoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int twitch_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int twitch_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    const char *cause = NULL;
    char *transport_error = NULL;
    br_http_response response = {0};
    char authorization[6 + 30 + 1];
    char status[64] = {0};
    /* Nil context sets the error and the finding is still published. The
     * fixed URL cannot fail to parse. */
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        memcpy(authorization, "OAuth ", 6);
        memcpy(authorization + 6, key.data, key.len);
        authorization[6 + key.len] = '\0';
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://id.twitch.tv/oauth2/validate",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        /* Exactly 200 verifies. 401 is unverified with a nil error. Every
         * other status is unexpected. Body and read errors are ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status == 200)
            result->verified = true;
        else if (response.status != 401) {
            snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
            cause = status;
        }
    }
    br_slice secret = {key.data, key.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) return twitch_fail(error, "cannot set TwitchAccessToken verification error");
    return 0;
}

static int twitch_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return twitch_fail(error, "invalid or uninitialized TwitchAccessToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Unique matches. Map order is unspecified upstream; first seen is one
     * possible order. TrimSpace cannot change this lowercase class. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 30) {
            twitch_fail(&owned_error, "invalid TwitchAccessToken capture");
            rc = -1;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            twitch_fail(&owned_error, "cannot create TwitchAccessToken result");
            rc = -1;
        } else if (verify && twitch_verify(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            twitch_fail(&owned_error, "cannot append TwitchAccessToken result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const twitch_keywords[] = {"twitch"};
static br_detector twitch_detector = {
    .type = 1010, .version = 0, .name = "TwitchAccessToken", .custom_name = "",
    .description = "Twitch is a live streaming service. Twitch access tokens can be used to access and modify data on the Twitch platform.",
    .keywords = twitch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = twitch_scan,
};

int br_twitchaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return twitch_fail(error, "invalid TwitchAccessToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&twitch_detector, "\\b([0-9a-z]{30})\\b", error) != 0)
        return -1;
    *out = &twitch_detector;
    return 0;
}
