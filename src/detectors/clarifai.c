/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clarifai/clarifai.go. */
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

static bool probe_clarifai(const br_scan_ctx *ctx, const char *url, const char *authorization)
{
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = url,
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 57};
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All Do errors are suppressed, including the shared ABI1 domain that also
     * contains adapter setup/allocation failures. Never classify error text. */
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    bool verified = rc == 0 && response.status >= 200 && response.status < 300;
    /* Body/read errors never affect verification. Source scan-defers Close-only
     * and holds the first successful Do response through fallback. ABI1 may
     * buffer eagerly and releases each response before the next probe instead. */
    br_http_release(ctx, &response);
    free(transport_error);
    return verified;
}

static int verify_clarifai(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char authorization[37]; /* Literal Key + SPACE + 32 captured ASCII bytes + NUL. */
    int n = snprintf(authorization, sizeof(authorization), "Key %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return fail(error, "cannot format Clarifai Authorization header");
    result->verified = probe_clarifai(ctx, "https://api.clarifai.com/v2/inputs", authorization);
    if (!result->verified)
        result->verified = probe_clarifai(ctx, "https://api.clarifai.com/v2/users/me", authorization);
    return 0; /* No verification-error setter, including when both probes fail. */
}

static int scan_clarifai(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Clarifai scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Both fixed requests share a context. Nil context fails the FIRST
         * constructor, so source skips this candidate without either probe. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Captured ASCII alphanumeric bytes make source TrimSpace a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Clarifai result");
        else if (verify) rc = verify_clarifai(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Clarifai result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"clarifai"};
static br_detector clarifai = {
    .type = 57, .version = 0, .name = "Clarifai", .custom_name = "",
    .description = "Clarifai is an AI platform for visual recognition. Clarifai API keys can be used to access and manage visual recognition models and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_clarifai,
};

int br_clarifai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Clarifai detector output");
    *out = NULL;
    if (br_key_pattern_init(&clarifai, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &clarifai;
    return 0;
}
