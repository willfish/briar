/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/finnhub/finnhub.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int finnhub_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool finnhub_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://finnhub.io/api/v1/calendar/economic?token=";
    char url[sizeof(prefix) + 20];
    _Static_assert(sizeof(url) == 71, "Finnhub URL must be 70 bytes plus NUL");
    /* Private captures are exactly 20 URL-safe lowercase alnum bytes. Source
     * prepares the COMPLETE URL BEFORE construction, without formatting,
     * escaping, a heap copy or a scanner-local cap/failure seam. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    if (!ctx) return false; /* Constructor failure SKIPS this occurrence. */
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. No
     * verification-error setter, diagnostic classifier or memory bypass. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack URL stays live through BOTH synchronous send and release.
     * Source scan-defers Close after successful Do and ignores body/read/close
     * errors. Eager buffering/release, Reader/close timing, private clients,
     * full native SANE/RE2 and global engine/output remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int finnhub_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return finnhub_fail(error, "invalid or uninitialized Finnhub scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences/duplicates. TrimSpace is a no-op for the
     * grammar. Finding resources precede complete URL preparation and skips. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = finnhub_fail(&owned_error, "cannot create Finnhub result");
        if (rc == 0 && verify) keep = finnhub_verify(ctx, br_captures_at(&keys, i), &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = finnhub_fail(&owned_error, "cannot append Finnhub result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const finnhub_keywords[] = {"finnhub"};
static br_detector finnhub_detector = {
    .type = 420, .version = 0, .name = "Finnhub", .custom_name = "",
    .description = "Finnhub is a financial data provider offering APIs to access market data. Finnhub API keys can be used to retrieve economic calendars, stock prices, and other financial information.",
    .keywords = finnhub_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = finnhub_scan,
};

int br_finnhub_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return finnhub_fail(error, "invalid Finnhub detector output");
    *out = NULL;
    if (br_key_pattern_init(&finnhub_detector, "\\b([0-9a-z]{20})\\b", error) != 0)
        return -1;
    *out = &finnhub_detector;
    return 0;
}
