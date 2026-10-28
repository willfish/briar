/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fxmarket/fxmarket.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fxmarket_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void fxmarket_verify(const br_scan_ctx *ctx, const char url[61], br_result *result)
{
    /* Constructor's known nil-context skip has passed. Borrow the complete
     * original unencoded stack URL through synchronous send AND release. */
    const br_header header = {"Content-Type", "application/json"};
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .headers = &header, .nheaders = 1, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding without setter/classifier. All successful-send 2xx verify;
     * body contents and read errors are deliberately ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close; ABI1 eagerly reads/releases owned responses,
     * even failures. Full Reader/native/private client/regexp and global engine/
     * output parity remain partial. Tests must use injected/offline transport. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int fxmarket_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fxmarket_fail(error, "invalid or uninitialized FXMarket scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates,
         * punctuation/case and actual fixed-width word-boundary captures. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fxmarket_fail(&owned_error, "cannot create FXMarket result");
        char url[61];
        if (rc == 0 && verify) {
            /* Finding THEN complete URL BEFORE constructor skip. KEY20 allows
             * bounded literal assembly, no encoder/formatter/heap copy or cap. */
            memcpy(url, "https://fxmarketapi.com/apilive?api_key=", 40);
            memcpy(url + 40, keys.items[i], 21); /* Complete original key + NUL. */
        }
        if (rc == 0 && (!verify || ctx)) {
            if (verify) fxmarket_verify(ctx, url, &result);
            if (br_results_push(out, &result) != 0)
                rc = fxmarket_fail(&owned_error, "cannot append FXMarket result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fxmarket_keywords[] = {"fxmarket"};
static br_detector fxmarket_detector = {
    .type = 381, .version = 0, .name = "FXMarket", .custom_name = "",
    .description = "Fxmarket is a financial market for trading currencies. Fxmarket API keys can be used to access and modify currency trading data.",
    .keywords = fxmarket_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fxmarket_scan,
};

int br_fxmarket_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fxmarket_fail(error, "invalid FXMarket detector output");
    *out = NULL;
    /* Preserve source's exact class and fixed-width word boundaries. Keyword
     * folding does NOT authorize capture normalization or alphabet validation. */
    if (br_key_pattern_init(&fxmarket_detector, "\\b([0-9Aa-zA-Z-_=]{20})\\b", error) != 0) return -1;
    *out = &fxmarket_detector;
    return 0;
}
