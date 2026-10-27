/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/countrylayer/countrylayer.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    COUNTRYLAYER_ABORT = -1, COUNTRYLAYER_KEEP = 0, COUNTRYLAYER_SKIP = 1
} countrylayer_outcome;

static int countrylayer_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static countrylayer_outcome countrylayer_verify(const br_scan_ctx *ctx, br_slice key,
                                                br_result *result, char **error)
{
    /* This 32-byte ASCII alphanumeric capture needs no escaping. The complete
     * bounded URL, including its NUL, stays borrowed through send AND release. */
    char url[sizeof("https://api.countrylayer.com/v2/all?access_key=") + 32];
    int n = snprintf(url, sizeof(url), "https://api.countrylayer.com/v2/all?access_key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        countrylayer_fail(error, "cannot format CountryLayer URL");
        return COUNTRYLAYER_ABORT;
    }
    /* Formatting precedes NewRequestWithContext's known nil-context skip. */
    if (!ctx) return COUNTRYLAYER_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * here: suppress the entire domain, without a setter or text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * do not affect status. Eager buffering/release, the full native client and
     * global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return COUNTRYLAYER_KEEP;
}

static int countrylayer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return countrylayer_fail(error, "invalid or uninitialized CountryLayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        countrylayer_outcome outcome = COUNTRYLAYER_KEEP;
        /* TrimSpace is a no-op; retain every occurrence. Finding resources must
         * fail before any known constructor skip, independently of verification. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            countrylayer_fail(&owned_error, "cannot create CountryLayer result");
            outcome = COUNTRYLAYER_ABORT;
        }
        if (outcome == COUNTRYLAYER_KEEP && verify)
            outcome = countrylayer_verify(ctx, key, &result, &owned_error);
        if (outcome == COUNTRYLAYER_KEEP && br_results_push(out, &result) != 0) {
            countrylayer_fail(&owned_error, "cannot append CountryLayer result");
            outcome = COUNTRYLAYER_ABORT;
        }
        br_result_clear(&result);
        if (outcome == COUNTRYLAYER_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const countrylayer_keywords[] = {"countrylayer"};
static br_detector countrylayer_detector = {
    .type = 526, .version = 0, .name = "CountryLayer", .custom_name = "",
    .description = "CountryLayer is a service that provides information about countries. CountryLayer API keys can be used to access this information.",
    .keywords = countrylayer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = countrylayer_scan,
};

int br_countrylayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return countrylayer_fail(error, "invalid CountryLayer detector output");
    *out = NULL;
    if (br_key_pattern_init(&countrylayer_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &countrylayer_detector;
    return 0;
}
