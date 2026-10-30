/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/restpackhtmltopdfapi/restpackhtmltopdfapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char restpack_url[] = "https://restpack.io/api/html2pdf/usage";

static int restpack_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool restpack_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return false;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Access-Token", key},
    };
    const br_http_request request = {
        .method = "GET", .url = restpack_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int restpack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return restpack_fail(error, "invalid or uninitialized RestpackHtmlToPdfAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Dispatch and extraction keyword are restpack. TrimSpace is a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 48)
            rc = restpack_fail(&owned_error, "invalid RestpackHtmlToPdfAPI capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = restpack_fail(&owned_error, "cannot create RestpackHtmlToPdfAPI result");
        else if (verify)
            keep = restpack_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = restpack_fail(&owned_error, "cannot append RestpackHtmlToPdfAPI result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const restpack_keywords[] = {"restpack"};
static br_detector restpack_detector = {
    .type = 517, .version = 0, .name = "RestpackHtmlToPdfAPI", .custom_name = "",
    .description = "Restpack is a service that provides APIs for converting HTML to PDF. Restpack API keys can be used to access and utilize this service.",
    .keywords = restpack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = restpack_scan,
};

int br_restpackhtmltopdfapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return restpack_fail(error, "invalid RestpackHtmlToPdfAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&restpack_detector, "\\b([0-9A-Za-z]{48})\\b", error) != 0)
        return -1;
    *out = &restpack_detector;
    return 0;
}
