/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pubnubpublishkey/pubnubpublishkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *publish, *subscribe;
} pubnub_patterns;

typedef enum { PUBNUB_ABORT = -1, PUBNUB_KEEP = 0 } pubnub_outcome;

static int pubnub_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pubnub_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    /* Only the publish key is redacted. The subscribe key is not a setter secret. */
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return pubnub_fail(error, "cannot set PubNubPublishKey verification error");
    return 0;
}

static pubnub_outcome pubnub_verify(const br_scan_ctx *ctx, br_slice key, br_slice sub,
                                    br_result *result, char **error)
{
    char url[192];
    int n = snprintf(url, sizeof(url),
                     "https://ps.pndsn.com/signal/%.*s/%.*s/0/ch1/0/%%22typing_on%%22?uuid=user-123",
                     (int)key.len, (const char *)key.data, (int)sub.len, (const char *)sub.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        pubnub_fail(error, "cannot format PubNubPublishKey URL");
        return PUBNUB_ABORT;
    }
    /* URL is complete before NewRequestWithContext. Nil context is an error, not a skip. */
    if (!ctx) {
        if (pubnub_cause(result, "net/http: nil Context", key, error) != 0) return PUBNUB_ABORT;
        return PUBNUB_KEEP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 400 && response.status != 403) {
        int written = snprintf(status_error, sizeof(status_error),
                               "unexpected HTTP response status %d", response.status);
        if (written < 0 || (size_t)written >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            pubnub_fail(error, "cannot format PubNubPublishKey status");
            return PUBNUB_ABORT;
        }
        cause = status_error;
    }
    int rc = pubnub_cause(result, cause, key, error);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? PUBNUB_KEEP : PUBNUB_ABORT;
}

static int pubnub_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const pubnub_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->publish || !patterns->subscribe || !out ||
        (!input.data && input.len))
        return pubnub_fail(error, "invalid or uninitialized PubNubPublishKey scan");
    size_t original_len = out->len;
    br_captures pubs = {0}, subs = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->publish, input, &pubs, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->subscribe, input, &subs, false, &owned_error);
    static const unsigned char slash[] = "/";
    for (size_t i = 0; rc == 0 && i < pubs.len; ++i) {
        for (size_t j = 0; rc == 0 && j < subs.len; ++j) {
            br_result result = {0};
            br_slice key = br_captures_at(&pubs, i);
            br_slice sub = br_captures_at(&subs, j);
            pubnub_outcome outcome = PUBNUB_KEEP;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", sub, "subscribe_key",
                                      (br_slice){slash, 1}) != 0) {
                pubnub_fail(&owned_error, "cannot create PubNubPublishKey result");
                outcome = PUBNUB_ABORT;
            } else if (verify)
                outcome = pubnub_verify(ctx, key, sub, &result, &owned_error);
            if (outcome == PUBNUB_ABORT) rc = -1;
            else if (br_results_push(out, &result) != 0) {
                pubnub_fail(&owned_error, "cannot append PubNubPublishKey result");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&pubs);
    br_captures_clear(&subs);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pubnub_keywords[] = {"sub-c-"};
static pubnub_patterns pubnub_state;
static br_detector pubnub_detector = {
    .type = 82, .version = 0, .name = "PubNubPublishKey", .custom_name = "",
    .description = "PubNub is a real-time communication platform that provides APIs for sending and "
                   "receiving messages. Publish keys are used to send messages to channels, while "
                   "subscribe keys are used to receive messages from channels.",
    .keywords = pubnub_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = pubnub_scan,
};

int br_pubnubpublishkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pubnub_fail(error, "invalid PubNubPublishKey detector output");
    *out = NULL;
    if (!pubnub_state.publish &&
        br_regex_compile("\\b(pub-c-[0-9a-z]{8}-[0-9a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
                         &pubnub_state.publish, error) != 0)
        return -1;
    if (!pubnub_state.subscribe &&
        br_regex_compile("\\b(sub-c-[0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
                         &pubnub_state.subscribe, error) != 0)
        return -1;
    pubnub_detector.state = &pubnub_state;
    *out = &pubnub_detector;
    return 0;
}
