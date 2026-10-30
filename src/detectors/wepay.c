/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/wepay/wepay.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_wepay(const br_scan_ctx *ctx, const char *key, const char *app_id, br_result *result)
{
    const br_header headers[] = {
        {"App-Token", key},
        {"App-Id", app_id},
        {"Api-Version", "3.0"},
        {"Accept", "application/json"},
        {"Unique-Key", "Unique-Key0"},
    };
    const br_http_request request = {
        .method = "GET",
        .url = "https://stage-api.wepay.com/payments?type=credit_card&credit_card=4003830171874018",
        .headers = headers, .nheaders = 5, .profile = BR_HTTP_SANE, .detector_type = 194,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_wepay(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid WePay scan");
    const br_regex *const *compiled = detector->state;
    br_captures apps = {0}, keys = {0};
    char app_id[7] = "";
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(compiled[0], input, &apps, false, &owned);
    if (!rc && apps.len) {
        br_slice last = br_captures_at(&apps, apps.len - 1);
        if (last.len != 6) rc = fail(&owned, "invalid WePay application id");
        else memcpy(app_id, last.data, 6);
    }
    if (!rc) rc = br_captures_find(compiled[1], input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len != 62) rc = fail(&owned, "invalid WePay capture");
        else if (br_finding_key_bytes(&result, 194, key, "key") != 0)
            rc = fail(&owned, "cannot create WePay result");
        else if (verify) {
            /* Fixed URL is complete; an empty App-Id is still sent, matching Header.Add. */
            if (!ctx) skip = true;
            else verify_wepay(ctx, keys.items[i], app_id, &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append WePay result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&apps);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"wepay"};
static br_regex *patterns[2];
static br_detector wepay = {
    .type = 194, .version = 0, .name = "WePay", .custom_name = "",
    .description = "WePay is an online payment service provider. WePay API keys can be used to "
                   "process payments and access account information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = patterns, .scan = scan_wepay,
};

int br_wepay_init(const br_detector **out, char **error)
{
    static const char *const prefixes[] = {"wepay"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WePay detector output");
    *out = NULL;
    if (!patterns[0] && br_regex_compile("\\b(\\d{6})\\b", &patterns[0], error) != 0) return -1;
    if (!patterns[1] &&
        br_regex_compile_prefixed(prefixes, 1, "\\b([a-zA-Z0-9_?]{62})\\b", &patterns[1], error) != 0)
        return -1;
    *out = &wepay;
    return 0;
}
