/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/oopspam/oopspam.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const unsigned char oopspam_body[] =
    "{\"checkForLength\":true,\"content\":\"Dear Agent, We are a manufacturing company which specializes in supplying Aluminum Rod with Zinc Alloy Rod to customers worldwide, based in Japan, Asia. We have been unable to follow up payments effectively for transactions with debtor customers in your country due to our distant locations, thus our reason for requesting for your services representation.\",\"senderIP\":\"185.234.219.246\",\"allowedCountries\":[\"it\",\"us\"],\"allowedLanguages\":[\"en\"]}";

static int oopspam_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The static body and captured key stay alive through send and release.
 * Timeout 0 selects the SANE default. Source never reads the response body. */
static void oopspam_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Api-Key", key},
    };
    const br_http_request request = {
        .method = "POST",
        .url = "https://api.oopspam.com/v1/spamdetection",
        .headers = headers,
        .nheaders = 2,
        .body = {oopspam_body, sizeof(oopspam_body) - 1},
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

static int oopspam_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return oopspam_fail(error, "invalid or uninitialized OOPSpam scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match. The upstream duplicate case is prefix
     * consumption, not a uniqueness map. Any nonzero, including +1, is fatal. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0 && !owned_error) owned_error = strdup("cannot scan OOPSpam matches");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure, including
         * +1, is fatal before the constructor skip, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = oopspam_fail(&owned_error, "cannot create OOPSpam result");
        else if (verify && !ctx) {
            /* Nil context drops after finding allocation, before prepare,
             * send, and release. A constructor skip is not an attempt. */
        } else {
            if (verify) oopspam_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = oopspam_fail(&owned_error, "cannot append OOPSpam result");
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

static const char *const oopspam_keywords[] = {"oopspam"};
static const char oopspam_capture[] = "\\b([a-zA-Z0-9]{40})\\b";
static br_detector oopspam_detector = {
    .type = 410,
    .version = 0,
    .name = "OOPSpam",
    .custom_name = "",
    .description = "OOPSpam is a spam detection service. OOPSpam API keys can be used to verify and detect spam content.",
    .keywords = oopspam_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = oopspam_scan,
};

int br_oopspam_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return oopspam_fail(error, "invalid OOPSpam detector output");
    *out = NULL;
    if (!oopspam_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(oopspam_keywords, 1, oopspam_capture, &regex, error) != 0)
            return -1;
        oopspam_detector.state = regex;
    }
    *out = &oopspam_detector;
    return 0;
}
