/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/glassnode/glassnode.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int glassnode_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool glassnode_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://api.glassnode.com/v1/metrics/indicators/sopr?a=btc&api_key=";
    /* The capture grammar fixes the complete URL size. Construct it before
     * NewRequestWithContext's nil-context skip, without another allocation. */
    char url[sizeof(prefix) + 27];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 27);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/allocation/Do error domain is false-kept.
     * No diagnostic classifier or error setter; response bodies are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original URL/header/capture values live through release. Ordinary ABI1
     * synthesized request storage ends at send return, not at Body.Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int glassnode_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return glassnode_fail(error, "invalid or uninitialized Glassnode scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Keep original nonoverlapping occurrences, case and duplicates. TrimSpace
     * is a no-op for this grammar. Own failures precede skip/suppression. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = glassnode_fail(&owned_error, "cannot create Glassnode result");
        if (rc == 0 && verify) keep = glassnode_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = glassnode_fail(&owned_error, "cannot append Glassnode result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const glassnode_keywords[] = {"glassnode"};
static br_detector glassnode_detector = {
    .type = 569, .version = 0, .name = "Glassnode", .custom_name = "",
    .description = "Glassnode is an on-chain market intelligence platform providing data and insights on blockchain and cryptocurrency markets. Glassnode API keys can be used to access various blockchain metrics and data points.",
    .keywords = glassnode_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = glassnode_scan,
};

int br_glassnode_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return glassnode_fail(error, "invalid Glassnode detector output");
    *out = NULL;
    if (br_key_pattern_init(&glassnode_detector, "\\b([0-9A-Za-z]{27})\\b", error) != 0)
        return -1;
    *out = &glassnode_detector;
    return 0;
}
