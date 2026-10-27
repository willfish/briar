/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/checkout/checkout.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } checkout_patterns;

static int checkout_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void checkout_verify(const br_scan_ctx *ctx, const char *key, const char *id, br_result *result)
{
    /* Source always uses sandbox, even for sk_ production-format credentials.
     * The fixed endpoint and 30-byte captured ID fit complete stack storage. */
    static const char prefix[] = "https://api.sandbox.checkout.com/customers/";
    char url[sizeof(prefix) + 30];
    snprintf(url, sizeof(url), "%s%s", prefix, id);
    const br_header headers[] = {{"Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 187,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire adapter/Do nonzero domain, including allocation/setup
     * failures that ABI1 cannot distinguish. Never classify error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only. ABI1's eager buffering and per-request
     * release remain lifecycle gaps; body/read errors do not affect status. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int checkout_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return checkout_fail(error, "invalid Checkout scan arguments");
    const checkout_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return checkout_fail(error, "uninitialized Checkout detector");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            /* Fixed method/URL and ASCII captures are otherwise constructor-safe.
             * Known nil-context construction failure skips this verify candidate. */
            if (verify && !ctx) continue;
            br_result result = {0};
            /* TrimSpace is a no-op. Preserve all occurrence products and their
             * original spelling; do not parse UUIDs, consume pairs or deduplicate. */
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                      br_captures_at(&ids, i), "id", (br_slice){0}) != 0)
                rc = checkout_fail(error, "out of memory creating Checkout result");
            else if (verify) checkout_verify(ctx, keys.items[k], ids.items[i], &result);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = checkout_fail(error, "out of memory appending Checkout result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc == 0 ? 0 : -1;
}

static checkout_patterns checkout_compiled;
static const char *const checkout_keywords[] = {"checkout"};
static const br_detector checkout_detector = {
    .type = 187, .version = 0, .name = "Checkout", .custom_name = "",
    .description = "Checkout is a global payment solution provider. "
                   "Checkout API keys can be used to process payments and manage customer data.",
    .keywords = checkout_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &checkout_compiled, .scan = checkout_scan,
};

int br_checkout_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return checkout_fail(error, "invalid Checkout detector output");
    *out = NULL;
    if (!checkout_compiled.key && br_regex_compile_prefixed(checkout_keywords, 1,
        "\\b((sk_|sk_test_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\b",
        &checkout_compiled.key, error) != 0) return -1;
    if (!checkout_compiled.id && br_regex_compile_prefixed(checkout_keywords, 1,
        "\\b(cus_[0-9a-zA-Z]{26})\\b", &checkout_compiled.id, error) != 0) return -1;
    *out = &checkout_detector;
    return 0;
}
