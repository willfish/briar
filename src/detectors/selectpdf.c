/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/selectpdf/selectpdf.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char selectpdf_prefix[] = "https://selectpdf.com/api2/convert/?key=";
static const char selectpdf_suffix[] = "&url=google.com";

static int selectpdf_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool selectpdf_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[sizeof(selectpdf_prefix) + 36 + sizeof(selectpdf_suffix) - 1];
    _Static_assert(sizeof(url) == 92, "SelectPDF URL is prefix, 36-byte key, and suffix");
    size_t at = sizeof(selectpdf_prefix) - 1;
    memcpy(url, selectpdf_prefix, at);
    memcpy(url + at, key, 36);
    at += 36;
    memcpy(url + at, selectpdf_suffix, sizeof(selectpdf_suffix));
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source assigns the shared client a 10s timeout only on the verify path. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int selectpdf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return selectpdf_fail(error, "invalid or uninitialized SelectPDF scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 36)
            rc = selectpdf_fail(&owned_error, "invalid SelectPDF capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = selectpdf_fail(&owned_error, "cannot create SelectPDF result");
        else if (verify)
            keep = selectpdf_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = selectpdf_fail(&owned_error, "cannot append SelectPDF result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const selectpdf_keywords[] = {"selectpdf"};
static br_detector selectpdf_detector = {
    .type = 641, .version = 0, .name = "SelectPDF", .custom_name = "",
    .description = "SelectPDF is a service that allows users to convert web pages to PDF documents. SelectPDF API keys can be used to perform these conversions programmatically.",
    .keywords = selectpdf_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = selectpdf_scan,
};

int br_selectpdf_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return selectpdf_fail(error, "invalid SelectPDF detector output");
    *out = NULL;
    if (br_key_pattern_init(&selectpdf_detector, "\\b([a-z0-9-]{36})\\b", error) != 0)
        return -1;
    *out = &selectpdf_detector;
    return 0;
}
