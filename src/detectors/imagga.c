/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/imagga/imagga.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int imagga_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void imagga_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The fixed request constructor's nil-context drop has already passed.
     * This is literal source formatting, NOT username/password Basic auth.
     * The grammar bounds the complete value to 6 + 72 bytes plus NUL. */
    br_header headers[2] = {{"Content-Type", "application/json"}};
    char authorization[79];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.imagga.com/v2/usage",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire shared preparation/Do error domain. Successful 2xx
     * responses verify without reading the body or inspecting read errors. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider originals survive release, including failed attempts. Ordinary
     * ABI1 synthesized headers/UA end at send return; do not retain them here. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int imagga_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return imagga_fail(error, "invalid or uninitialized Imagga scan");
    const br_regex *pattern = *(br_regex *const *)detector->state;
    if (!pattern) return imagga_fail(error, "uninitialized Imagga pattern");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(pattern, input, &keys, false, &owned_error);
    /* TrimSpace is a no-op for this ASCII alphabet. Preserve occurrence order,
     * duplicates and 72-byte prefixes, including context-dependent leading '='. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 72)
            rc = imagga_fail(&owned_error, "invalid Imagga capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = imagga_fail(&owned_error, "cannot create Imagga result");
        else if (!verify || ctx) {
            if (verify) imagga_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = imagga_fail(&owned_error, "cannot append Imagga result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_regex *imagga_pattern;
static const char *const imagga_keywords[] = {"imagga"};
static const br_detector imagga_detector = {
    .type = 349, .version = 0, .name = "Imagga", .custom_name = "",
    .description = "Imagga is a cloud-based image recognition and categorization service. Imagga API keys can be used to access and utilize these image processing services.",
    .keywords = imagga_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &imagga_pattern, .scan = imagga_scan,
};

int br_imagga_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return imagga_fail(error, "invalid Imagga detector output");
    *out = NULL;
    if (!imagga_pattern && br_regex_compile_prefixed(imagga_keywords, 1,
        "\\b([a-z0-9A-Z=]{72})", &imagga_pattern, error) != 0) return -1;
    *out = &imagga_detector;
    return 0;
}
