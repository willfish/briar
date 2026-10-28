/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/exchangeratesapi/exchangeratesapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int exchangeratesapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes constructor skip, NOT verification rejection. Shared
 * setup/allocation/Do failures retain the original unverified finding. */
static bool exchangeratesapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://api.exchangeratesapi.io/v1/latest?access_key=";
    /* Complete URL precedes the context-bound constructor. Exact 32-byte ASCII
     * captures need no encoder, formatter, heap copy or arbitrary cap. */
    char url[sizeof(base) + 32];
    _Static_assert(sizeof(url) == 86, "ExchangeRatesAPI URL is 85 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 32);
    url[sizeof(base) - 1 + 32] = '\0';
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Every 2xx verifies, ignoring all body/read errors, even empty non-NULL
     * errors. Suppress the WHOLE mixed shared setup/allocation/Do domain without
     * a setter or diagnostic classifier; Do failure is never constructor skip. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Stack URL lives through synchronous send AND release. Source scan-defers
     * Close without reading; ABI1 buffers/releases eagerly, even failed sends.
     * Full Reader/deferred-close/native-client/regexp and global source,
     * engine/output parity remain partial. Shared native guards stay unchanged. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int exchangeratesapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                  br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return exchangeratesapi_fail(error, "invalid or uninitialized ExchangeRatesAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Preserve occurrences/duplicates, with no token
         * validation, local filtering or cache. Finding resources precede URL
         * construction, constructor skips and suppressed verification failures. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = exchangeratesapi_fail(&owned_error, "cannot create ExchangeRatesAPI result");
        if (rc == 0 && verify) keep = exchangeratesapi_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = exchangeratesapi_fail(&owned_error, "cannot append ExchangeRatesAPI result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const exchangeratesapi_keywords[] = {"exchangerates"};
static br_detector exchangeratesapi_detector = {
    .type = 379, .version = 0, .name = "ExchangeRatesAPI", .custom_name = "",
    .description = "ExchangeRatesAPI provides exchange rate data for various currencies. The API key can be used to access and retrieve this data.",
    .keywords = exchangeratesapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = exchangeratesapi_scan,
};

int br_exchangeratesapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return exchangeratesapi_fail(error, "invalid ExchangeRatesAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&exchangeratesapi_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &exchangeratesapi_detector;
    return 0;
}
