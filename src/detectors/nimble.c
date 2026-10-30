/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nimble/nimble.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int nimble_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Bearer value is borrowed through synchronous send and release.
 * Timeout 0 selects the SANE default. Source never reads the body. */
static void nimble_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[38];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 30);
    authorization[37] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://app.nimble.com/api/v1/myself",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    /* A reached send stays unverified for every cause, including NULL.
     * Do not invent or publish transport text, and do not call a setter. */
    free(transport_error);
    if (send_rc == 0 && response.status >= 200 && response.status < 300)
        result->verified = true; /* body_error does not change a successful send. */
    br_http_release(ctx, &response); /* One release for this attempted send. */
}

static int nimble_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nimble_fail(error, "invalid or uninitialized Nimble scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match. The upstream duplicate case is prefix
     * consumption, not a uniqueness map. Any nonzero, including +1, is fatal. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0 && !owned_error) owned_error = strdup("cannot scan Nimble matches");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure, including
         * +1, is fatal before the constructor skip, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nimble_fail(&owned_error, "cannot create Nimble result");
        else if (verify && !ctx) {
            /* Nil context drops after finding allocation, before prepare,
             * send, and release. A constructor skip is not an attempt. */
        } else {
            if (verify) nimble_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = nimble_fail(&owned_error, "cannot append Nimble result");
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

static const char *const nimble_keywords[] = {"nimble"};
static const char nimble_capture[] = "\\b([a-zA-Z0-9]{30})\\b";
static br_detector nimble_detector = {
    .type = 266,
    .version = 0,
    .name = "Nimble",
    .custom_name = "",
    .description = "Nimble is a customer relationship management (CRM) tool designed to help businesses manage their customer interactions and data. Nimble API keys can be used to access and modify customer records and other CRM functionalities.",
    .keywords = nimble_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = nimble_scan,
};

int br_nimble_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nimble_fail(error, "invalid Nimble detector output");
    *out = NULL;
    if (!nimble_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(nimble_keywords, 1, nimble_capture, &regex, error) != 0)
            return -1;
        nimble_detector.state = regex;
    }
    *out = &nimble_detector;
    return 0;
}
