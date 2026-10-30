/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pepipost/pepipost.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int pepipost_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pepipost_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pepipost_fail(error, "invalid or uninitialized Pepipost scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pepipost_fail(&owned_error, "cannot create Pepipost result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.pepipost.com/v5.1/domain/getDomains?domain=pepisandbox.com";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {{"api_key", (const char *)key.data}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pepipost_fail(&owned_error, "cannot append Pepipost result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pepipost_keywords[] = {"pepipost", "netcore"};
static br_detector pepipost_detector = {
    .type = 117, .version = 0, .name = "Pepipost", .custom_name = "",
    .description = "Pepipost is an email delivery service. The API keys can be used to send and track emails through Pepipost's infrastructure.",
    .keywords = pepipost_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pepipost_scan,
};

int br_pepipost_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pepipost_fail(error, "invalid Pepipost detector output");
    *out = NULL;
    if (br_key_pattern_init(&pepipost_detector, "\\b([a-zA-Z-0-9]{32})\\b", error) != 0) return -1;
    *out = &pepipost_detector;
    return 0;
}
