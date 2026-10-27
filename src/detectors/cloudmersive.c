/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudmersive/cloudmersive.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int cloudmersive_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void cloudmersive_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const unsigned char payload[] = "{\"AddressString\":\"string\",\"CapitalizationMode\":\"string\"}";
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Apikey", key}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.cloudmersive.com/validate/address/parse",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 358,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines adapter setup/allocation and Do failures. Source suppresses
     * this whole domain; never classify by error text or call an error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Eager buffering,
     * per-request release, POST redirects and native client configuration remain
     * partial. Body/read errors do not change the source status-only decision. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int cloudmersive_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cloudmersive_fail(error, "invalid or uninitialized Cloudmersive scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL, constant payload and captured ASCII are otherwise
         * constructor-safe. Known nil-context construction failure skips only
         * verification candidates, never no-verification extraction. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; preserve every occurrence and its whole key. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = cloudmersive_fail(error, "out of memory creating Cloudmersive result");
        else if (verify) cloudmersive_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cloudmersive_fail(error, "out of memory appending Cloudmersive result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cloudmersive_keywords[] = {"cloudmersive"};
static br_detector cloudmersive_detector = {
    .type = 358, .version = 0, .name = "Cloudmersive", .custom_name = "",
    .description = "Cloudmersive provides a suite of APIs for data validation, conversion, and security. "
                   "Cloudmersive API keys can be used to access these services.",
    .keywords = cloudmersive_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cloudmersive_scan,
};

int br_cloudmersive_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cloudmersive_fail(error, "invalid Cloudmersive detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloudmersive_detector, "\\b([a-z0-9-]{36})\\b", error) != 0) return -1;
    *out = &cloudmersive_detector;
    return 0;
}
