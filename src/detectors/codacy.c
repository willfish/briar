/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/codacy/codacy.go. */
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

static void verify_codacy(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Go Header.Add canonicalizes source's "api-token" to "Api-Token".
     * The complete captured value stays borrowed through send and release. */
    const br_header headers[] = {{"Accept", "application/json"}, {"Api-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.codacy.com/api/v3/user",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the whole shared setup/allocation + Do error domain. Error text
     * does not identify a constructor stage; no verification error is stored. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY, whereas
     * ABI1 can eagerly buffer/release; full native client/lifecycle parity is open. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_codacy(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Codacy scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the captured mixed ASCII alphanumeric class. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Codacy result");
        if (!rc && verify) {
            if (!ctx) { br_result_clear(&result); continue; } /* Known constructor failure skips only this occurrence. */
            verify_codacy(ctx, keys.items[i], &result);
        }
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Codacy result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"codacy"};
static br_detector codacy = {
    .type = 185, .version = 0, .name = "Codacy", .custom_name = "",
    .description = "Codacy is an automated code review tool that helps developers and teams improve code quality. Codacy API tokens can be used to access and manage code quality reports and settings.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_codacy,
};

int br_codacy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Codacy detector output");
    *out = NULL;
    if (br_key_pattern_init(&codacy, "\\b([0-9A-Za-z]{20})\\b", error)) return -1;
    *out = &codacy;
    return 0;
}
