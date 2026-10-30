/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/storychief/storychief.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char storychief_url[] = "https://api.storychief.io/1.0/users?page=1&count=10";
static int storychief_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void storychief_verify(const br_scan_ctx *ctx, const char *key, const char *url,
                       const char *payload, size_t payload_len, const char *authorization,
                       br_result *result)
{
    char value1[1104];
    snprintf(value1, sizeof(value1), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", value1},
    };
    const br_http_request request = {
        .method = "GET", .url = url,
        .headers = headers, .nheaders = 2,
        .body = {payload ? (const unsigned char *)payload : NULL, payload_len},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 340,
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

static int storychief_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return storychief_fail(error, "invalid or uninitialized Storychief scan");
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
        if (verify) {
            url = storychief_url;
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
            rc = storychief_fail(&owned, "cannot create Storychief result");
        else if (verify)
            storychief_verify(ctx, key, url, payload, payload_len, authorization, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = storychief_fail(&owned, "cannot append Storychief result");
        br_result_clear(&result);
        free(authorization);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const storychief_keywords[] = {"storychief"};
static br_detector storychief_detector = {
    .type = 340, .version = 0, .name = "Storychief", .custom_name = "",
    .description = "Storychief is a content marketing platform that helps in creating, distributing, and measuring content. Storychief API keys can be used to access and manage content and integrations within the platform.",
    .keywords = storychief_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = storychief_scan,
};

int br_storychief_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return storychief_fail(error, "invalid Storychief detector output");
    *out = NULL;
    if (!storychief_detector.state && br_regex_compile_prefixed(storychief_keywords, 1,
            "\\b([a-zA-Z0-9_\\-.]{940,1000})", (br_regex **)&storychief_detector.state, error) != 0)
        return -1;
    *out = &storychief_detector;
    return 0;
}
