/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/vatlayer/vatlayer.go. */
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

static bool contains(br_slice body, const char *needle)
{
    return br_slice_find(body, (br_slice){(const unsigned char *)needle, strlen(needle)}, 0) != SIZE_MAX;
}

static int verify_vatlayer(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://www.apilayer.net/api/validate?access_key=%s&vat_number=LU26375245&format=1", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format VatLayer URL");
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) && !response.body_error &&
        response.status >= 200 && response.status < 300 &&
        (contains(response.body, "vat_number") ||
         contains(response.body, "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"")))
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_vatlayer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized VatLayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create VatLayer result");
            outcome = -1;
        } else if (verify)
            outcome = verify_vatlayer(ctx, keys.items[i], &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append VatLayer result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"vatlayer"};
static br_detector vatlayer = {
    .type = 496, .version = 0, .name = "VatLayer", .custom_name = "",
    .description = "VatLayer is a service that provides VAT number validation and VAT rate data for businesses. VatLayer keys can be used to access this service and retrieve VAT-related information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_vatlayer,
};

int br_vatlayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid VatLayer detector output");
    *out = NULL;
    if (!vatlayer.state && br_key_pattern_init(&vatlayer, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &vatlayer;
    return 0;
}
