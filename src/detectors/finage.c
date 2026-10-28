/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/finage/finage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int finage_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is constructor skip, not rejection. All shared setup/allocation/Do
 * errors instead retain the original false finding, without setters/classifiers. */
static bool finage_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://api.finage.co.uk/symbol-list/crypto?apikey=";
    /* Complete URL BEFORE construction: fixed 39-byte original ASCII capture,
     * no formatter/encoder/heap copy or arbitrary cap/failure seam. */
    char url[sizeof(base) + 39];
    _Static_assert(sizeof(url) == 91, "Finage URL is 90 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1); memcpy(url + sizeof(base) - 1, key.data, 39); url[90] = '\0';
    if (!ctx) return false;
    unsigned char dedup_key[44];
    memcpy(dedup_key, "423:", 4); memcpy(dedup_key + 4, key.data, 39); dedup_key[43] = '\0';
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key) - 1}, /* Mandatory complete 423:TOKEN, no NUL in slice. */
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Keep the nonempty key: ABI1's unchanged shared coalescing guard rejects
     * BEFORE every injected/native send callback. Suppress the WHOLE mixed
     * shared send domain, never classify its text or drop this finding. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && response.body_error == NULL)
        result->verified = response.status >= 200 && response.status < 300;
    /* Status success above is UNPROVEN behind the real guard. Singleflight
     * ReadAll must succeed BEFORE source Do success; non-NULL body_error would
     * represent that buffering failure, not the source's ignored replay body.
     * Full URL/dedup storage lives through synchronous send AND release. Source
     * scan-defers Close; full coalescing/replay/cancellation, Reader/close/client,
     * regexp and global source/engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int finage_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return finage_fail(error, "invalid or uninitialized Finage scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i); bool keep = true;
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates, with
         * no validation/filter/cache. Finding resources precede URL/constructor. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = finage_fail(&owned_error, "cannot create Finage result");
        if (rc == 0 && verify) keep = finage_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = finage_fail(&owned_error, "cannot append Finage result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const finage_keywords[] = {"finage"};
static br_detector finage_detector = {
    .type = 423, .version = 0, .name = "Finage", .custom_name = "",
    .description = "Finage provides financial data APIs for stocks, forex, and cryptocurrencies. Finage API keys can be used to access and retrieve financial data.",
    .keywords = finage_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = finage_scan,
};

int br_finage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return finage_fail(error, "invalid Finage detector output");
    *out = NULL;
    if (!finage_detector.state) {
        br_regex *regex = NULL;
        /* finage is DISPATCH ONLY. Extraction is DIRECT and case-sensitive. */
        if (br_regex_compile("\\b(API_KEY[0-9A-Z]{32})\\b", &regex, error) != 0) return -1;
        finage_detector.state = regex;
    }
    *out = &finage_detector;
    return 0;
}
