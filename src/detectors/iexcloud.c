/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/iexcloud/iexcloud.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { IEXCLOUD_ABORT = -1, IEXCLOUD_KEEP = 0, IEXCLOUD_DROP = 1 } iexcloud_outcome;
enum { IEXCLOUD_KEY_SIZE = 35 };

static int iexcloud_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static iexcloud_outcome iexcloud_verify(const br_scan_ctx *ctx, br_slice key,
                                       br_result *result, char **error)
{
    static const char prefix[] = "https://cloud.iexapis.com/v1/stock/aapl/quote?token=";
    char *url = malloc(sizeof(prefix) + IEXCLOUD_KEY_SIZE);
    if (!url) {
        iexcloud_fail(error, "cannot construct Iexcloud URL");
        return IEXCLOUD_ABORT;
    }
    /* The checked, fixed ASCII capture needs no escaping. Assemble the whole
     * source fmt.Sprintf value before the nil-context constructor can drop it. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, IEXCLOUD_KEY_SIZE);
    url[sizeof(prefix) - 1 + IEXCLOUD_KEY_SIZE] = '\0';
    if (!ctx) {
        free(url);
        return IEXCLOUD_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses the whole Do error domain. ABI1 mixes shared setup
     * failures into it; neither signs nor diagnostic text classify them. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore bodies/read errors at every status. Keep original URL/captures
     * through one ordinary release, including failed shared preparation.
     * Synthesized request/header-array/User-Agent end at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return IEXCLOUD_KEEP;
}

static int iexcloud_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return iexcloud_fail(error, "invalid or uninitialized Iexcloud scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        iexcloud_outcome outcome = IEXCLOUD_KEEP;
        /* TrimSpace is a no-op for this alphabet. Keep original occurrences
         * and duplicates; do not impose Iexapis's distinct sk_ grammar. */
        if (key.len != IEXCLOUD_KEY_SIZE) {
            iexcloud_fail(&owned_error, "invalid Iexcloud capture");
            outcome = IEXCLOUD_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            iexcloud_fail(&owned_error, "cannot create Iexcloud result");
            outcome = IEXCLOUD_ABORT;
        } else if (verify) {
            outcome = iexcloud_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == IEXCLOUD_KEEP && br_results_push(out, &result) != 0) {
            iexcloud_fail(&owned_error, "cannot append Iexcloud result");
            outcome = IEXCLOUD_ABORT;
        }
        br_result_clear(&result);
        if (outcome == IEXCLOUD_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const iexcloud_keywords[] = {"iexcloud"};
static br_detector iexcloud_detector = {
    .type = 557, .version = 0, .name = "Iexcloud", .custom_name = "",
    .description = "IEX Cloud is a financial data platform providing access to a wide range of financial data APIs. IEX Cloud tokens can be used to access and retrieve financial data.",
    .keywords = iexcloud_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = iexcloud_scan,
};

int br_iexcloud_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return iexcloud_fail(error, "invalid Iexcloud detector output");
    *out = NULL;
    if (br_key_pattern_init(&iexcloud_detector, "\\b([a-z0-9_]{35})\\b", error) != 0)
        return -1;
    *out = &iexcloud_detector;
    return 0;
}
