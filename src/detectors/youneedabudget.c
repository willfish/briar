/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/youneedabudget/youneedabudget.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char ynab_url[] = "https://api.youneedabudget.com/v1/user";

static int ynab_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool ynab_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[72];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 64);
    authorization[71] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = ynab_url, .headers = headers, .nheaders = 1,
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

static int ynab_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ynab_fail(error, "invalid or uninitialized YouNeedABudget scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 64)
            rc = ynab_fail(&owned_error, "invalid YouNeedABudget capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ynab_fail(&owned_error, "cannot create YouNeedABudget result");
        else if (verify)
            keep = ynab_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ynab_fail(&owned_error, "cannot append YouNeedABudget result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ynab_keywords[] = {"youneedabudget"};
static br_detector ynab_detector = {
    .type = 464, .version = 0, .name = "YouNeedABudget", .custom_name = "",
    .description = "YouNeedABudget is a budgeting tool that allows users to manage their personal finances. The API keys can be used to access and modify a user's financial data.",
    .keywords = ynab_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ynab_scan,
};

int br_youneedabudget_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ynab_fail(error, "invalid YouNeedABudget detector output");
    *out = NULL;
    if (br_key_pattern_init(&ynab_detector, "\\b([0-9a-f]{64})\\b", error) != 0)
        return -1;
    *out = &ynab_detector;
    return 0;
}
