/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/checio/checio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int checio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void checio_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"X-Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.chec.io/v1/products?limit=25",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 643,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire nonzero adapter/Do domain. ABI1 cannot distinguish
     * setup/allocation failures from Do errors; never classify by error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close only until FromData returns. ABI1 releases per request
     * and may eagerly buffer the body; body/read errors do not affect status. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int checio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return checio_fail(error, "invalid or uninitialized ChecIO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* The fixed method/URL and ASCII key are otherwise constructor-safe.
         * Known nil-context creation failure skips only verification candidates. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace cannot change the capture. Raw includes the entire pk_ key. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = checio_fail(error, "out of memory creating ChecIO result");
        else if (verify) checio_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = checio_fail(error, "out of memory appending ChecIO result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const checio_keywords[] = {"checio"};
static br_detector checio_detector = {
    .type = 643, .version = 0, .name = "ChecIO", .custom_name = "",
    .description = "ChecIO is an eCommerce platform that provides APIs for managing products, carts, and orders. "
                   "ChecIO API keys can be used to access and manage these eCommerce resources.",
    .keywords = checio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = checio_scan,
};

int br_checio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return checio_fail(error, "invalid ChecIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&checio_detector, "\\b(pk_[a-z0-9]{45})\\b", error) != 0) return -1;
    *out = &checio_detector;
    return 0;
}
