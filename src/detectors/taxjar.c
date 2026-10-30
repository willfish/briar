/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/taxjar/taxjar.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void verify_taxjar(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[48];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.taxjar.com/v2/categories",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 151,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
}

static int scan_taxjar(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Taxjar scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            rc = fail(error, "out of memory creating Taxjar result");
        } else if (verify && !ctx) {
            br_result_clear(&result);
            continue;
        } else if (verify) verify_taxjar(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append Taxjar result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const taxjar_keywords[] = {"taxjar"};
static br_detector taxjar_detector = {
    .type = 151, .version = 0, .name = "Taxjar", .custom_name = "",
    .description = "Taxjar is a sales tax API that allows businesses to automate sales tax calculations, reporting, and filings. Taxjar API keys can be used to access and manage these services.",
    .keywords = taxjar_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_taxjar,
};

int br_taxjar_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Taxjar detector output");
    *out = NULL;
    if (br_key_pattern_init(&taxjar_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &taxjar_detector;
    return 0;
}
