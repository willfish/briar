/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hybiscus/hybiscus.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int hybiscus_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void hybiscus_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The fixed-URL constructor has succeeded before Header.Add. Capture
     * storage already supplies a trailing NUL, so no key projection is needed. */
    const br_header headers[] = {
        {"Accept", "application/vnd.hybiscus+json; version=3"},
        {"X-Api-Key", (const char *)key.data}, /* Go canonicalizes X-API-KEY. */
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.hybiscus.dev/api/v1/get-remaining-quota",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses every Do error. Shared ABI1 preparation failures are
     * in that same mixed domain, without classification or an error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Release once even after failed preparation;
     * provider originals survive release, synthesized headers/UA only send.
     * This eager release does not reproduce source's scan-deferred closes. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int hybiscus_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hybiscus_fail(error, "invalid or uninitialized Hybiscus scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* TrimSpace cannot change this ASCII capture. Keep source-order original
     * occurrences and duplicates, without semantic validation or filtering. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 43)
            rc = hybiscus_fail(&owned_error, "invalid Hybiscus capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = hybiscus_fail(&owned_error, "cannot create Hybiscus result");
        if (rc == 0 && verify) {
            /* Finding construction precedes NewRequestWithContext's nil drop;
             * provider headers are assembled only after that constructor. */
            if (!ctx) keep = false;
            else hybiscus_verify(ctx, key, &result);
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = hybiscus_fail(&owned_error, "cannot append Hybiscus result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const hybiscus_keywords[] = {"hybiscus"};
static br_detector hybiscus_detector = {
    .type = 773, .version = 0, .name = "Hybiscus", .custom_name = "",
    .description = "Hybiscus is a service that provides API keys to access its resources and perform operations. These keys should be kept secure to prevent unauthorized access.",
    .keywords = hybiscus_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hybiscus_scan,
};

int br_hybiscus_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hybiscus_fail(error, "invalid Hybiscus detector output");
    *out = NULL;
    if (br_key_pattern_init(&hybiscus_detector, "\\b([0-9a-zA-Z]{43})\\b", error) != 0)
        return -1;
    *out = &hybiscus_detector;
    return 0;
}
