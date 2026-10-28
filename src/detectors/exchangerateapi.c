/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/exchangerateapi/exchangerateapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int exchangerateapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int exchangerateapi_verify(const br_scan_ctx *ctx, br_slice key,
                                  br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &key, 1) != 0)
            return exchangerateapi_fail(error, "cannot set ExchangeRateAPI verification error");
        return 0; /* Constructor failure RETAINS this false finding. */
    }
    /* Source constructs the request BEFORE preparing Authorization. Private
     * captures are exactly 24 lowercase hex bytes: no formatter or heap copy. */
    static const char prefix[] = "Bearer ";
    char authorization[sizeof(prefix) + 24];
    _Static_assert(sizeof(authorization) == 32, "Bearer value must be 31 bytes plus NUL");
    memcpy(authorization, prefix, sizeof(prefix) - 1);
    memcpy(authorization + sizeof(prefix) - 1, key.data, key.len);
    authorization[sizeof(prefix) - 1 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        /* Preserve the literal source URL: the key is NOT a path component. */
        .method = "GET", .url = "https://v6.exchangerate-api.com/v6/latest/USD",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* Deliberately suppress the WHOLE mixed shared setup/allocation/Do error
     * domain. Do not classify its diagnostics or turn them into scan failures. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.status == 200) result->verified = true;
        else if (response.status != 403) {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = exchangerateapi_fail(error, "cannot format ExchangeRateAPI verification status");
            else cause = status_error;
        }
    }
    /* Source's final setter has exactly ONE secret: the token, not Bearer/URL.
     * NULL cause is a no-op; any nonzero setter result is fatal. Copy before
     * release, while the complete stack Authorization remains borrowed too. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = exchangerateapi_fail(error, "cannot set ExchangeRateAPI verification error");
    /* Source drains/closes after status and ignores every body/read/drain error.
     * ABI1's logical empty body cannot express http.NoBody identity. Reader/
     * drain timing, eager buffering/release, private clients, full SANE/RE2 and
     * global engine/output behavior remain partial; no local filtering/cache. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int exchangerateapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return exchangerateapi_fail(error, "invalid or uninitialized ExchangeRateAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Original occurrences/duplicates, not a unique set. TrimSpace is a no-op
     * for lowercase hex. Allocate each finding BEFORE constructor handling. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = exchangerateapi_fail(&owned_error, "cannot create ExchangeRateAPI result");
        if (rc == 0 && verify)
            rc = exchangerateapi_verify(ctx, br_captures_at(&keys, i), &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = exchangerateapi_fail(&owned_error, "cannot append ExchangeRateAPI result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const exchangerateapi_keywords[] = {"exchangerate", "exchange-rate"};
static br_detector exchangerateapi_detector = {
    .type = 360, .version = 0, .name = "ExchangeRateAPI", .custom_name = "",
    .description = "An API key for determining the exchange rate of currencies",
    .keywords = exchangerateapi_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = exchangerateapi_scan,
};

int br_exchangerateapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return exchangerateapi_fail(error, "invalid ExchangeRateAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&exchangerateapi_detector, "\\b([a-f0-9]{24})\\b", error) != 0)
        return -1;
    *out = &exchangerateapi_detector;
    return 0;
}
