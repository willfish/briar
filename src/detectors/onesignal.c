/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/onesignal/onesignal.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct onesignal_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    struct onesignal_attempt *previous;
    char *authorization;
} onesignal_attempt;

static int onesignal_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void onesignal_release(const br_scan_ctx *ctx, onesignal_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt->authorization);
    free(attempt);
}

static onesignal_attempt *onesignal_request(br_slice key)
{
    onesignal_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (onesignal_attempt){0};
    /* Source encodes "<key>:" and prefixes Basic; the helper returns that full
     * value. Keep it alive through send and the one release. */
    if (br_http_basic_auth(key, (br_slice){0}, &attempt->authorization, NULL) != 0) {
        free(attempt);
        return NULL;
    }
    attempt->headers[0] = (br_header){"Accept", "application/vnd.onesignal+json; version=3"};
    attempt->headers[1] = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://onesignal.com/api/v1/apps",
        .headers = attempt->headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 835,
    };
    return attempt;
}

static int onesignal_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return onesignal_fail(error, "invalid or uninitialized OneSignal scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    onesignal_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* The UUID grammar cannot contain whitespace, so TrimSpace is a no-op. */
        if (key.len != 36 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = onesignal_fail(error, "cannot create OneSignal result");
        if (rc == 0 && verify && !ctx) {
            /* Fixed-URL constructor rejects nil before Accept/Authorization. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            onesignal_attempt *attempt = onesignal_request(key);
            if (!attempt) rc = onesignal_fail(error, "cannot construct OneSignal request");
            else {
                char *transport_error = NULL;
                /* Source suppresses the whole mixed preparation/Do domain and
                 * never sets a verification error; bodies are ignored. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else onesignal_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = onesignal_fail(error, "cannot append OneSignal result");
        br_result_clear(&result);
    }
    /* Successful responses close LIFO after publication; failed attempts were
     * released immediately once with their original authorization. */
    while (deferred) {
        onesignal_attempt *previous = deferred->previous;
        onesignal_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const onesignal_keywords[] = {"onesignal"};
static br_detector onesignal_detector = {
    .type = 835, .version = 0, .name = "Onesignal", .custom_name = "",
    .description = "OneSignal is a customer engagement platform that enables businesses to send push notifications, in-app messages, SMS, and emails. OneSignal API keys can be used to access and send messages through these channels.",
    .keywords = onesignal_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = onesignal_scan,
};

int br_onesignal_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return onesignal_fail(error, "invalid OneSignal detector output");
    *out = NULL;
    if (br_key_pattern_init(&onesignal_detector,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &onesignal_detector;
    return 0;
}
