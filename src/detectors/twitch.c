/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twitch/twitch.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TW_ABORT = -1, TW_KEEP = 0 } tw_outcome;

static int tw_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static tw_outcome tw_verify(const br_scan_ctx *ctx, const char *id, const char *secret,
                            br_result *result, char **error)
{
    char body[128], length[16], status_error[64];
    int n = snprintf(body, sizeof(body),
                     "client_id=%s&client_secret=%s&grant_type=client_credentials", id, secret);
    if (n < 0 || (size_t)n >= sizeof(body))
        return tw_fail(error, "cannot format Twitch form body"), TW_ABORT;
    int ln = snprintf(length, sizeof(length), "%d", n);
    if (ln < 0 || (size_t)ln >= sizeof(length))
        return tw_fail(error, "cannot format Twitch content length"), TW_ABORT;
    const char *cause = NULL;
    char *send_error = NULL;
    br_http_response response = {0};
    bool sent = false;
    /* url.Values.Encode and the request body exist before the nil-context error. */
    if (!ctx) cause = "net/http: nil Context";
    else {
        const br_header headers[] = {
            {"Content-Type", "application/x-www-form-urlencoded"},
            {"Content-Length", length},
        };
        const br_http_request request = {
            .method = "POST", .url = "https://id.twitch.tv/oauth2/token",
            .headers = headers, .nheaders = 2,
            .body = {(const unsigned char *)body, (size_t)n},
            .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error;
        } else if (response.status == 200) {
            result->verified = true;
        } else if (response.status != 400 && response.status != 403) {
            int written = snprintf(status_error, sizeof(status_error),
                                   "unexpected http response status %d", response.status);
            if (written < 0 || (size_t)written >= sizeof(status_error))
                return tw_fail(error, "cannot format Twitch status"), TW_ABORT;
            cause = status_error;
        }
    }
    /* Only the client id is passed to SetVerificationError. */
    br_slice secret_id = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret_id, 1);
    if (sent) br_http_release(ctx, &response);
    free(send_error);
    return rc == 0 ? TW_KEEP : TW_ABORT;
}

static int tw_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tw_fail(error, "invalid or uninitialized Twitch scan");
    size_t original_len = out->len;
    br_captures matches = {0};
    char *owned_error = NULL;
    /* Both source patterns are identical, so one unique set is both id and secret. */
    int rc = br_captures_find(detector->state, input, &matches, true, &owned_error);
    const br_slice colon = {(const unsigned char *)":", 1};
    for (size_t i = 0; rc == 0 && i < matches.len; ++i) {
        for (size_t s = 0; rc == 0 && s < matches.len; ++s) {
            if (i == s) continue;
            br_result result = {0};
            tw_outcome outcome = TW_KEEP;
            br_slice id = br_captures_at(&matches, i);
            br_slice secret = br_captures_at(&matches, s);
            if (br_finding_pair_bytes(&result, detector->type, id, "id", secret, "secret", colon) != 0)
                rc = tw_fail(&owned_error, "cannot create Twitch result");
            else if (verify)
                outcome = tw_verify(ctx, matches.items[i], matches.items[s], &result, &owned_error);
            if (rc == 0 && outcome == TW_ABORT) rc = -1;
            if (rc == 0 && outcome == TW_KEEP && br_results_push(out, &result) != 0)
                rc = tw_fail(&owned_error, "cannot append Twitch result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&matches);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tw_keywords[] = {"twitch"};
static br_detector tw_detector = {
    .type = 310, .version = 0, .name = "Twitch", .custom_name = "",
    .description = "Twitch is a live streaming service. Twitch client credentials can be used to access and modify data on the Twitch platform.",
    .keywords = tw_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = tw_scan,
};

int br_twitch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tw_fail(error, "invalid Twitch detector output");
    *out = NULL;
    if (br_key_pattern_init(&tw_detector, "\\b([0-9a-z]{30})\\b", error) != 0) return -1;
    *out = &tw_detector;
    return 0;
}
