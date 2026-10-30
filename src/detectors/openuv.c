/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/openuv/openuv.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int openuv_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int openuv_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return openuv_fail(error, "invalid or uninitialized Openuv scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase-alphanumeric grammar. */
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = openuv_fail(&owned_error, "cannot create Openuv result");
        if (rc == 0 && verify) {
            /* Fixed-URL constructor failure (nil context) drops this candidate
             * before the provider header, send or release. */
            if (ctx) {
                const br_header headers[] = {{"x-access-token", keys.items[i]}};
                const br_http_request request = {
                    .method = "GET", .url = "https://api.openuv.io/api/v1/uv?lat=-33.34&lng=115.342",
                    .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
                    .detector_type = detector->type,
                };
                br_http_response response = {0};
                char *send_error = NULL;
                /* Suppress the whole mixed preparation/Do domain with no
                 * setter; every successful-send 2xx verifies and bodies and
                 * read errors are ignored. */
                if (br_http_send(ctx, &request, &response, &send_error) == 0)
                    result.verified = response.status >= 200 && response.status < 300;
                br_http_release(ctx, &response);
                free(send_error);
            } else {
                br_result_clear(&result);
                continue;
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = openuv_fail(&owned_error, "cannot append Openuv result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const openuv_keywords[] = {"openuv"};
static br_detector openuv_detector = {
    .type = 504, .version = 0, .name = "Openuv", .custom_name = "",
    .description = "Openuv provides UV index data through its API. These API keys can be used to access UV index information.",
    .keywords = openuv_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = openuv_scan,
};

int br_openuv_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return openuv_fail(error, "invalid Openuv detector output");
    *out = NULL;
    if (br_key_pattern_init(&openuv_detector, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &openuv_detector;
    return 0;
}
