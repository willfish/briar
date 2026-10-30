/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/serphouse/serphouse.go. */
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

static void verify_serphouse(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[68];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n != 67) return;
    const br_header headers[] = {
        {"Accept", "application/vnd.serphouse+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.serphouse.com/account/info",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 613,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_serphouse(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Serphouse scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len != 60) rc = fail(&owned, "invalid Serphouse capture");
        else if (br_finding_key_bytes(&result, 613, key, "key") != 0)
            rc = fail(&owned, "cannot create Serphouse result");
        else if (verify) {
            /* Fixed URL is complete; nil context is the constructor skip. */
            if (!ctx) skip = true;
            else verify_serphouse(ctx, keys.items[i], &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Serphouse result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"serphouse"};
static br_detector serphouse = {
    .type = 613, .version = 0, .name = "Serphouse", .custom_name = "",
    .description = "Serphouse is a service that provides search engine result page data. "
                   "Serphouse API keys can be used to access this data and perform various operations on it.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_serphouse,
};

int br_serphouse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Serphouse detector output");
    *out = NULL;
    if (br_key_pattern_init(&serphouse, "\\b([0-9A-Za-z]{60})\\b", error) != 0) return -1;
    *out = &serphouse;
    return 0;
}
