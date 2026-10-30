/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/partnerstack/partnerstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int partnerstack_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Accept and Authorization stay alive through synchronous send and release.
 * Timeout 0 selects the SANE default. Source never reads the body. */
static void partnerstack_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[72];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 64);
    authorization[71] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.partnerstack.com/api/v2/partnerships",
        .headers = headers,
        .nheaders = 2,
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

static int partnerstack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return partnerstack_fail(error, "invalid or uninitialized Partnerstack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match. The upstream duplicate case is prefix
     * consumption, not a uniqueness map. Any nonzero, including +1, is fatal. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0 && !owned_error) owned_error = strdup("cannot scan Partnerstack matches");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure, including
         * +1, is fatal before the constructor skip, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = partnerstack_fail(&owned_error, "cannot create Partnerstack result");
        else if (verify && !ctx) {
            /* Nil context drops after finding allocation, before prepare,
             * send, and release. A constructor skip is not an attempt. */
        } else {
            if (verify) partnerstack_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = partnerstack_fail(&owned_error, "cannot append Partnerstack result");
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

static const char *const partnerstack_keywords[] = {"partnerstack"};
static const char partnerstack_capture[] = "\\b([0-9A-Za-z]{64})\\b";
static br_detector partnerstack_detector = {
    .type = 545,
    .version = 0,
    .name = "Partnerstack",
    .custom_name = "",
    .description = "PartnerStack is a partner management platform that helps companies manage their partner programs. PartnerStack API keys can be used to access and manage these programs.",
    .keywords = partnerstack_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = partnerstack_scan,
};

int br_partnerstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return partnerstack_fail(error, "invalid Partnerstack detector output");
    *out = NULL;
    if (!partnerstack_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(partnerstack_keywords, 1, partnerstack_capture, &regex, error) != 0)
            return -1;
        partnerstack_detector.state = regex;
    }
    *out = &partnerstack_detector;
    return 0;
}
