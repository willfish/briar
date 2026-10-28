/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/foursquare/foursquare.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int foursquare_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void foursquare_verify(const br_scan_ctx *ctx, const char url[187], br_result *result)
{
    /* Constructor's known nil-context skip has passed. The complete stack URL
     * remains borrowed through synchronous send AND release. */
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
     * even failures. Reader/native/private client/regexp and global engine/output
     * parity remain partial. Verification tests must stay injected/offline. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int foursquare_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return foursquare_fail(error, "invalid or uninitialized FourSquare scan");
    size_t original_len = out->len;
    br_captures values = {0}; char *owned_error = NULL;
    /* Both source roles have IDENTICAL patterns. One occurrence collection is
     * sufficient, but both loops preserve the full original KEY-major N-squared
     * product, including duplicates/selfpairs. No sets/equality skip/span cap. */
    int rc = br_captures_find(detector->state, input, &values, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < values.len; ++k) {
        for (size_t s = 0; rc == 0 && s < values.len; ++s) {
            br_result result = {0};
            /* TrimSpace is a no-op. Complete Raw/parts/RawV2 resources BEFORE
             * constructor skip or ordinary shared-domain suppression. */
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&values, k), "key",
                                      br_captures_at(&values, s), "secret", (br_slice){0}) != 0)
                rc = foursquare_fail(&owned_error, "cannot create FourSquare result");
            char url[187];
            if (rc == 0 && verify) {
                /* Finding THEN complete URL BEFORE constructor. Exact KEY48 +
                 * SECRET48 permit bounded assembly, not formatting/encoding or
                 * a heap copy/cap. Keep original ID-first query and fixed date. */
                memcpy(url, "https://api.foursquare.com/v2/venues/trending?client_id=", 56);
                memcpy(url + 56, values.items[k], 48);
                memcpy(url + 104, "&client_secret=", 15);
                memcpy(url + 119, values.items[s], 48);
                memcpy(url + 167, "&v=20211019&near=LA", 20); /* Includes final NUL. */
            }
            if (rc == 0 && (!verify || ctx)) {
                if (verify) foursquare_verify(ctx, url, &result);
                if (br_results_push(out, &result) != 0)
                    rc = foursquare_fail(&owned_error, "cannot append FourSquare result");
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&values);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const foursquare_keywords[] = {"foursquare"};
static br_detector foursquare_detector = {
    .type = 454, .version = 0, .name = "FourSquare", .custom_name = "",
    .description = "Foursquare is a technology company that uses location intelligence to build meaningful consumer experiences and business solutions. Foursquare API keys can be used to access and interact with their services.",
    .keywords = foursquare_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = foursquare_scan,
};

int br_foursquare_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return foursquare_fail(error, "invalid FourSquare detector output");
    *out = NULL;
    if (br_key_pattern_init(&foursquare_detector, "\\b([0-9A-Z]{48})\\b", error) != 0) return -1;
    *out = &foursquare_detector;
    return 0;
}
