/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cliengo/cliengo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int cliengo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void cliengo_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const char base[] = "https://api.cliengo.com/1.0/account?api_key=";
    char url[sizeof(base) + 36];
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key, 37); /* Fixed 36-byte ASCII capture plus NUL. */
    unsigned char dedup_key[41] = "710:";
    memcpy(dedup_key + 4, key, 37);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 710,
        .dedup_key = {dedup_key, 40}, /* Exact 710:KEY bytes, excluding NUL. */
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Deliberately keep the key: ABI1 currently rejects coalescing BEFORE any
     * injected/native send callback. This provider is partial, not successful
     * verification support. ALL send failures are suppressed, without text
     * classification, including the guard and unified adapter/setup failures. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.body_error == NULL)
        result->verified = response.status >= 200 && response.status < 300;
    /* Future supported sends must treat ANY read-error pointer (even "") as
     * Do failure: source singleflight ReadAll runs before status inspection.
     * The predicate above is currently blocked by the unchanged core guard.
     * Source closes the base body and scan-defers closing each replay; close
     * errors are ignored. ABI1 requires release once after each send attempt. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int cliengo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cliengo_fail(error, "invalid or uninitialized Cliengo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII captures leave nil context as the known
         * constructor failure: source skips rather than appends the candidate. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; the UUID shape imposes no version-bit checks. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = cliengo_fail(error, "out of memory creating Cliengo result");
        else if (verify) cliengo_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cliengo_fail(error, "out of memory appending Cliengo result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cliengo_keywords[] = {"cliengo"};
static br_detector cliengo_detector = {
    .type = 710, .version = 0, .name = "Cliengo", .custom_name = "",
    .description = "Cliengo is a chatbot service that helps businesses convert website visitors into leads. "
                   "Cliengo API keys can be used to access and manage the chatbot configurations and data.",
    .keywords = cliengo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cliengo_scan,
};

int br_cliengo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cliengo_fail(error, "invalid Cliengo detector output");
    *out = NULL;
    if (br_key_pattern_init(&cliengo_detector,
            "\\b([0-9a-f]{8}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &cliengo_detector;
    return 0;
}
