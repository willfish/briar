/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bscscan/bscscan.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_bscscan(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0 ? -1 : 0;
    static const char prefix[] = "https://api.bscscan.com/api?module=account&action=balance&address=0x70F657164e5b75689b64B7fd1fA275F334f28e18&apikey=";
    char url[sizeof(prefix) + 34]; /* Fixed 34-byte uppercase-alphanumeric capture. */
    int n = snprintf(url, sizeof(url), "%s%s", prefix, key);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    const br_http_request request = {.method = "GET", .url = url,
        .profile = BR_HTTP_SANE, .detector_type = 910};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200) {
        if (response.body_error) cause = response.body_error;
        else result->verified = br_slice_find(response.body,
            (br_slice){(const unsigned char *)"NOTOK", 5}, 0) == SIZE_MAX;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Source supplies ZERO secrets, so even echoed keys/URLs remain unredacted.
     * Copy a borrowed body error before releasing the response that owns it. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0;
}

static int scan_bscscan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_bscscan, error);
    /* Shared occurrence scanning appends eagerly; roll back this invocation
     * on resource failure without touching any findings supplied by the caller. */
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc != 0 ? -1 : 0;
}

static const char *const keywords[] = {"bscscan"};
static br_detector bscscan = {
    .type = 910, .version = 0, .name = "BscScan", .custom_name = "",
    .description = "BscScan is a block explorer and analytics platform for Binance Smart Chain. BscScan API keys can be used to access data from the Binance Smart Chain blockchain.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bscscan,
};

int br_bscscan_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BscScan detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&bscscan, "\\b([0-9A-Z]{34})\\b", error) != 0) return -1;
    *out = &bscscan;
    return 0;
}
