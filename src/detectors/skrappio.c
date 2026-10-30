/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/skrappio/skrappio.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int skrappio_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int skrappio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return skrappio_fail(error, "invalid or uninitialized Skrappio scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 42 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = skrappio_fail(&owned_error, "cannot create Skrappio result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.skrapp.io/api/v2/account";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            static const char h0[] = "application/json";
            const char *h1 = (const char *)key.data;
            const br_header headers[] = {{"Content-Type", h0}, {"X-Access-Key", h1}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 2,
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
            rc = skrappio_fail(&owned_error, "cannot append Skrappio result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const skrappio_keywords[] = {"skrapp"};
static br_detector skrappio_detector = {
    .type = 245, .version = 0, .name = "Skrappio", .custom_name = "",
    .description = "Skrapio is a service used for email verification and enrichment. Skrapio API keys can be used to access and utilize its services for verifying and enriching email addresses.",
    .keywords = skrappio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = skrappio_scan,
};

int br_skrappio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return skrappio_fail(error, "invalid Skrappio detector output");
    *out = NULL;
    if (br_key_pattern_init(&skrappio_detector, "\\b([a-z0-9A-Z]{42})\\b", error) != 0) return -1;
    *out = &skrappio_detector;
    return 0;
}
