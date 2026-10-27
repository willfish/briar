/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/codemagic/codemagic.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_codemagic(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Go Header.Add canonicalizes source's "x-auth-token". Borrow the complete
     * captured value through synchronous send/release, without an auth copy. */
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-Auth-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.codemagic.io/apps",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress ALL combined adapter setup/allocation + Do failures. Do not infer
     * constructor stages from error text or store verification errors. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Every 2xx verifies irrespective of body/read errors. Source scan-defers
     * Close ONLY; eager per-request release/full native client parity is open. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_codemagic(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Codemagic scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* BuildRegex(AlphaNumPattern, "_", 43) cannot capture whitespace. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Codemagic result");
        if (!rc && verify) {
            if (!ctx) { br_result_clear(&result); continue; } /* Constructor SKIP follows finding preparation. */
            verify_codemagic(ctx, keys.items[i], &result);
        }
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Codemagic result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"codemagic"};
static br_detector codemagic = {
    .type = 845, .version = 0, .name = "Codemagic", .custom_name = "",
    .description = "Codemagic is a CI/CD platform for mobile app projects. Codemagic API keys can be used to automate and manage the build and deployment process of mobile applications.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_codemagic,
};

int br_codemagic_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Codemagic detector output");
    *out = NULL;
    if (br_key_pattern_init(&codemagic, "\\b([0-9a-zA-Z_]{43})\\b", error)) return -1;
    *out = &codemagic;
    return 0;
}
