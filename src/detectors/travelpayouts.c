/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/travelpayouts/travelpayouts.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int travelpayouts_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void travelpayouts_verify(const br_scan_ctx *ctx, const char *key, const char *url,
                       const char *payload, size_t payload_len, const char *authorization,
                       br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url,
        .body = {payload ? (const unsigned char *)payload : NULL, payload_len},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 662,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Client.Do errors stay unverified with no verification error. Body and
     * close errors are ignored; ABI1 releases every send, including failure. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        bool ok = response.status >= 200 && response.status < 300;
        result->verified = ok;
    }
    (void)key;
    br_http_release(ctx, &response);
    free(transport_error);
    (void)authorization;
}

static int travelpayouts_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return travelpayouts_fail(error, "invalid or uninitialized TravelPayouts scan");
    size_t original = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* Duplicates remain. The captured alphabet makes TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        const char *key = keys.items[i];
        const char *url = NULL;
        const char *payload = NULL;
        size_t payload_len = 0;
        char *authorization = NULL;
        char url_buf[256];
        if (verify) {
            int n = snprintf(url_buf, sizeof(url_buf), "https://api.travelpayouts.com/v2/prices/latest?currency=usd&limit=5&token=%s", key);
            if (n < 0 || (size_t)n >= sizeof(url_buf)) {
                rc = travelpayouts_fail(&owned, "cannot build TravelPayouts URL");
                break;
            }
            url = url_buf;
            /* Nil context is the reachable NewRequestWithContext error and skips
             * this candidate after URL, body and Basic construction. */
            if (!ctx) {
                free(authorization);
                authorization = NULL;
                continue;
            }
        }
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = travelpayouts_fail(&owned, "cannot create TravelPayouts result");
        else if (verify)
            travelpayouts_verify(ctx, key, url, payload, payload_len, authorization, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = travelpayouts_fail(&owned, "cannot append TravelPayouts result");
        br_result_clear(&result);
        free(authorization);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const travelpayouts_keywords[] = {"travelpayouts"};
static br_detector travelpayouts_detector = {
    .type = 662, .version = 0, .name = "TravelPayouts", .custom_name = "",
    .description = "TravelPayouts is a travel affiliate network that provides access to various travel-related APIs. TravelPayouts keys can be used to interact with these APIs to retrieve travel data and earn commissions on bookings.",
    .keywords = travelpayouts_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = travelpayouts_scan,
};

int br_travelpayouts_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return travelpayouts_fail(error, "invalid TravelPayouts detector output");
    *out = NULL;
    if (!travelpayouts_detector.state && br_regex_compile_prefixed(travelpayouts_keywords, 1,
            "\\b([a-z0-9]{32})\\b", (br_regex **)&travelpayouts_detector.state, error) != 0)
        return -1;
    *out = &travelpayouts_detector;
    return 0;
}
