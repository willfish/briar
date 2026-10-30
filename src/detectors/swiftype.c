/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/swiftype/swiftype.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char swiftype_url[] = "https://search-api.swiftype.com/api/v1/engines/bookstore/document_types/books/search.json";
static int swiftype_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void swiftype_verify(const br_scan_ctx *ctx, const char *key, const char *url,
                       const char *payload, size_t payload_len, const char *authorization,
                       br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = url,
        .headers = headers, .nheaders = 1,
        .body = {payload ? (const unsigned char *)payload : NULL, payload_len},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 675,
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

static int swiftype_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return swiftype_fail(error, "invalid or uninitialized Swiftype scan");
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
        char payload_buf[128];
        if (verify) {
            url = swiftype_url;
            int bn = snprintf(payload_buf, sizeof(payload_buf), "{\"auth_token\":\"%s\",\"q\": \"gatsby\"}", key);
            if (bn < 0 || (size_t)bn >= sizeof(payload_buf)) {
                rc = swiftype_fail(&owned, "cannot build Swiftype body");
                break;
            }
            payload = payload_buf;
            payload_len = (size_t)bn;
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
            rc = swiftype_fail(&owned, "cannot create Swiftype result");
        else if (verify)
            swiftype_verify(ctx, key, url, payload, payload_len, authorization, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = swiftype_fail(&owned, "cannot append Swiftype result");
        br_result_clear(&result);
        free(authorization);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const swiftype_keywords[] = {"swiftype"};
static br_detector swiftype_detector = {
    .type = 675, .version = 0, .name = "Swiftype", .custom_name = "",
    .description = "Swiftype is a search technology that provides powerful search solutions for websites and applications. Swiftype keys can be used to access and manipulate search data.",
    .keywords = swiftype_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = swiftype_scan,
};

int br_swiftype_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return swiftype_fail(error, "invalid Swiftype detector output");
    *out = NULL;
    if (!swiftype_detector.state && br_regex_compile_prefixed(swiftype_keywords, 1,
            "\\b([a-zA-z-0-9]{6}\\_[a-zA-z-0-9]{6}\\-[a-zA-z-0-9]{6})\\b", (br_regex **)&swiftype_detector.state, error) != 0)
        return -1;
    *out = &swiftype_detector;
    return 0;
}
