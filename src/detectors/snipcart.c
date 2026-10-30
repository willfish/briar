/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/snipcart/snipcart.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { SNIP_ABORT = -1, SNIP_KEEP = 0, SNIP_SKIP = 1 } snip_outcome;

static int snip_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static snip_outcome snip_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Encode token+":" before NewRequestWithContext. Encoding failure is
     * fatal. Nil context is checked before URL parse and drops this
     * occurrence. The fixed URL cannot fail to parse. */
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return SNIP_ABORT;
    }
    snip_outcome outcome = SNIP_KEEP;
    if (!ctx) {
        outcome = SNIP_SKIP;
    } else {
        const br_header headers[] = {
            {"Accept", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "GET", .url = "https://app.snipcart.com/api/orders",
            .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Do failures stay unverified with no setter. Body and read errors
         * are ignored. Only 2xx verifies. */
        if (br_http_send(ctx, &request, &response, &transport_error) == 0)
            result->verified = response.status >= 200 && response.status < 300;
        br_http_release(ctx, &response);
        free(transport_error);
    }
    free(authorization);
    return outcome;
}

static int snip_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return snip_fail(error, "invalid or uninitialized Snipcart scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        snip_outcome outcome = SNIP_KEEP;
        if (key.len != 75) {
            snip_fail(&owned_error, "invalid Snipcart capture");
            outcome = SNIP_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            snip_fail(&owned_error, "cannot create Snipcart result");
            outcome = SNIP_ABORT;
        } else if (verify) {
            outcome = snip_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == SNIP_KEEP && br_results_push(out, &result) != 0) {
            snip_fail(&owned_error, "cannot append Snipcart result");
            outcome = SNIP_ABORT;
        }
        br_result_clear(&result);
        if (outcome == SNIP_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const snip_keywords[] = {"snipcart"};
static br_detector snip_detector = {
    .type = 505, .version = 0, .name = "Snipcart", .custom_name = "",
    .description = "Snipcart is an easy-to-implement shopping cart platform for developers. Snipcart API keys can be used to access and manage e-commerce functionalities.",
    .keywords = snip_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = snip_scan,
};

int br_snipcart_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return snip_fail(error, "invalid Snipcart detector output");
    *out = NULL;
    if (br_key_pattern_init(&snip_detector, "\\b([0-9A-Za-z_]{75})\\b", error) != 0)
        return -1;
    *out = &snip_detector;
    return 0;
}
