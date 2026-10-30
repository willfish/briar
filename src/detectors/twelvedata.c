/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twelvedata/twelvedata.go. */
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

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

/* The complete URL precedes NewRequest. A constructor or body-read error drops
 * only this candidate. Any body that does not contain "401" is verified,
 * including a non-2xx status. Do errors are ignored and still append. */
static int verify_twelvedata(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://api.twelvedata.com/earliest_timestamp?symbol=AAPL&interval=1day&apikey=%s",
                     (const char *)secret.data);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format TwelveData URL");
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 137,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error) rc = 1;
        else {
            static const unsigned char marker[] = "401";
            result->verified = br_slice_find(response.body, (br_slice){marker, 3}, 0) == SIZE_MAX;
        }
    }
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_twelvedata(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TwelveData scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create TwelveData finding");
        } else if (verify) {
            int status = verify_twelvedata(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append TwelveData finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"twelvedata"};
static br_detector twelvedata = {
    .type = 137, .version = 0, .name = "TwelveData", .custom_name = "",
    .description = "TwelveData provides financial data APIs for stock, forex, cryptocurrency, and more. TwelveData API keys can be used to access and retrieve this financial data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_twelvedata,
};

int br_twelvedata_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TwelveData detector output");
    *out = NULL;
    if (br_key_pattern_init(&twelvedata, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &twelvedata;
    return 0;
}
