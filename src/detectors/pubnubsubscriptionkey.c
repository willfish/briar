/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pubnubsubscriptionkey. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pubnub_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pubnub_set(br_result *result, const char *cause, char **error)
{
    /* Source passes no secrets. A URL or body that contains the key stays visible. */
    return br_result_set_verification_error(result, cause, NULL, 0)
        ? pubnub_fail(error, "cannot set PubNubSubscriptionKey verification error") : 0;
}

static bool pubnub_contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > body.len) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int pubnub_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char prefix[] = "https://ps.pndsn.com/v2/objects/";
    static const char suffix[] = "/uuids";
    _Static_assert(sizeof(prefix) - 1 + 42 + sizeof(suffix) - 1 == 80, "PubNub URL is 80 bytes");
    if (key.len != 42) return pubnub_fail(error, "invalid PubNubSubscriptionKey capture");
    /* Concatenation is an argument to NewRequestWithContext, so it precedes the
     * nil-context error. That error is retained; the candidate is not dropped. */
    char url[81];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 42);
    memcpy(url + sizeof(prefix) - 1 + 42, suffix, sizeof(suffix));
    if (!ctx) return pubnub_set(result, "net/http: nil Context", error);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status == 403) {
        if (response.body_error) cause = response.body_error;
        else if (pubnub_contains(response.body, "Objects not enabled for this subscriber key."))
            result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = pubnub_fail(error, "cannot format PubNubSubscriptionKey status");
        else cause = status_error;
    }
    if (!rc) rc = pubnub_set(result, cause, error);
    /* 200/401 do not read the body. Source defers drain+close inside the verifier. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int pubnub_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pubnub_fail(error, "invalid or uninitialized PubNubSubscriptionKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* TrimSpace cannot change this capture. Occurrences, including duplicates, stay. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pubnub_fail(&owned_error, "cannot create PubNubSubscriptionKey result");
        else if (verify && pubnub_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = pubnub_fail(&owned_error, "cannot append PubNubSubscriptionKey result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pubnub_keywords[] = {"sub-c-"};
static br_detector pubnub_detector = {
    .type = 83, .version = 0, .name = "PubNubSubscriptionKey", .custom_name = "",
    .description = "PubNub is a real-time communication platform. A PubNub Subscription Key allows access to the PubNub API for subscribing to channels and receiving messages.",
    .keywords = pubnub_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pubnub_scan,
};

int br_pubnubsubscriptionkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pubnub_fail(error, "invalid PubNubSubscriptionKey detector output");
    *out = NULL;
    if (!pubnub_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(sub-c-[0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
                             &regex, error) != 0)
            return -1;
        pubnub_detector.state = regex;
    }
    *out = &pubnub_detector;
    return 0;
}
