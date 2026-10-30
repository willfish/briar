/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/requestfinance/requestfinance.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_requestfinance(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Fixed method and URL. Nil context is the only constructor failure that
     * drops the candidate; the header value is the raw key, not a Bearer token. */
    if (!ctx) return 1;
    const br_header headers[] = {{"Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.request.finance/invoices",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc == 0 ? 0 : -1;
}

static int scan_requestfinance(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized RequestFinance scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        if (verify && !ctx) continue;
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0 ||
            (verify && verify_requestfinance(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory creating RequestFinance result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"requestfinance"};
static br_detector requestfinance = {
    .type = 964, .version = 0, .name = "RequestFinance", .custom_name = "",
    .description = "Request Finance is a platform for managing and automating invoices and payments. Request Finance credentials can be used to access and manage these financial operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_requestfinance,
};

int br_requestfinance_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid RequestFinance detector output");
    *out = NULL;
    if (br_key_pattern_init(&requestfinance,
            "\\b([0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7})\\b", error) != 0)
        return -1;
    *out = &requestfinance;
    return 0;
}
