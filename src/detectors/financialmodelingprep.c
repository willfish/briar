/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/financialmodelingprep/financialmodelingprep.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int financialmodelingprep_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void financialmodelingprep_verify(const br_scan_ctx *ctx, const char url[114], br_result *result)
{
    /* Constructor's known nil-context skip has passed. Borrow the entire stack
     * URL through synchronous send AND release; only common UA is added. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, keeping a
     * false finding without setter/classifier. Source ReadAll precedes EVERY
     * status: ANY non-NULL read error (even empty) retains false, never drops. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.body_error == NULL) {
        static const unsigned char marker[] = "[ \"";
        bool valid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        /* Exact binary substring only, including after NUL/invalid UTF-8 or in
         * unrelated text. No JSON parsing, trimming or whitespace normalization. */
        result->verified = response.status >= 200 && response.status < 300 && valid;
    }
    /* Source scan-defers Close only after successful ReadAll (no Close on read
     * error). ABI1 always eagerly releases owned responses, even failures. Full
     * Reader/private-native client/regexp and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int financialmodelingprep_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return financialmodelingprep_fail(error, "invalid or uninitialized FinancialModelingPrep scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences and duplicates,
         * without hex validation, local filtering or verification cache. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = financialmodelingprep_fail(&owned_error, "cannot create FinancialModelingPrep result");
        char url[114];
        if (rc == 0 && verify) {
            /* Finding THEN complete URL BEFORE constructor skip. Exact KEY32
             * permits direct bounded assembly, no formatter/encoder/heap copy. */
            memcpy(url, "https://financialmodelingprep.com/api/v3/financial-statement-symbol-lists?apikey=", 81);
            memcpy(url + 81, keys.items[i], 33); /* Original key32 plus NUL. */
        }
        if (rc == 0 && (!verify || ctx)) {
            if (verify) financialmodelingprep_verify(ctx, url, &result);
            if (br_results_push(out, &result) != 0)
                rc = financialmodelingprep_fail(&owned_error, "cannot append FinancialModelingPrep result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const financialmodelingprep_keywords[] = {"financialmodelingprep"};
static br_detector financialmodelingprep_detector = {
    .type = 406, .version = 0, .name = "FinancialModelingPrep", .custom_name = "",
    .description = "FinancialModelingPrep provides financial data APIs. The API keys can be used to access financial data and related services.",
    .keywords = financialmodelingprep_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = financialmodelingprep_scan,
};

int br_financialmodelingprep_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return financialmodelingprep_fail(error, "invalid FinancialModelingPrep detector output");
    *out = NULL;
    if (br_key_pattern_init(&financialmodelingprep_detector, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &financialmodelingprep_detector;
    return 0;
}
