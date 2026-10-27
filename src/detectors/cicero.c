/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cicero/cicero.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_cicero(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    static const char prefix[] = "https://cicero.azavea.com/v3.1/account/credits_remaining?key=";
    char url[sizeof(prefix) + 40]; /* Complete fixed 40-byte key, plus terminating NUL. */
    int n = snprintf(url, sizeof(url), "%s%s", prefix, key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format Cicero verification URL");
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {.method = "GET", .url = url,
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 477};
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All Do errors are suppressed. ABI1 also mixes adapter allocation/setup
     * failures into this nonzero domain; never infer their stage from text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close-only until scan return without draining. ABI1 may
     * already have buffered the body and releases per request instead. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0; /* No verification-error setter, even for non-2xx or Do failures. */
}

static int scan_cicero(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Cicero scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the known
         * constructor failure. Source skips the candidate, not the invocation. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Captured lowercase ASCII alphanumeric bytes make TrimSpace a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Cicero result");
        else if (verify) rc = verify_cicero(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Cicero result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"cicero"};
static br_detector cicero = {
    .type = 477, .version = 0, .name = "Cicero", .custom_name = "",
    .description = "Cicero is a service provided by Azavea that offers various geospatial and civic data APIs. Cicero keys can be used to access and interact with these APIs.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_cicero,
};

int br_cicero_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Cicero detector output");
    *out = NULL;
    if (br_key_pattern_init(&cicero, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &cicero;
    return 0;
}
