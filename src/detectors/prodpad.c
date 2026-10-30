/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/prodpad/prodpad.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char prodpad_url[] = "https://api.prodpad.com/v1/tags";
/* Bearer is 6 bytes. The pinned Sprintf includes the following space. */
_Static_assert(sizeof(prodpad_url) - 1 == 31, "Prodpad URL is 31 bytes");
_Static_assert(sizeof("Bearer ") - 1 + 64 == 71, "Prodpad authorization is 71 bytes");

static int prodpad_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int prodpad_authorization(br_slice key, char value[72], char **error)
{
    if (!key.data || key.len != 64 || memchr(key.data, 0, key.len))
        return prodpad_fail(error, "invalid Prodpad key capture");
    int n = snprintf(value, 72, "Bearer %.*s", 64, (const char *)key.data);
    /* Every count other than the complete 71-byte value is fatal, including +1. */
    return n == 71 ? 0 : prodpad_fail(error, "cannot format Prodpad authorization");
}

static int prodpad_verify(const br_scan_ctx *ctx, br_slice key, bool *verified, char **error)
{
    /* Nil context was dropped by the caller before either header is built. */
    char authorization[72];
    if (prodpad_authorization(key, authorization, error) != 0) return -1;
    /* Source spells "accept". Header.Add canonicalizes it to Accept. This
     * helper copies the name as given, so the canonical name is passed here. */
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    br_http_request request = {
        .method = "GET", .url = prodpad_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 842,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    bool accepted = sent == 0 && response.status >= 200 && response.status < 300;
    /* Send failure, including a consumed NULL leaf, stays false with no setter
     * and no invented diagnostic. Body bytes and body_error are ignored.
     * Keep the original URL, key and both headers live through one release. */
    br_http_release(ctx, &response);
    free(send_error);
    *verified = accepted;
    return 0;
}

static int prodpad_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return prodpad_fail(error, "invalid or uninitialized Prodpad scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Occurrences stay in order, including duplicates. The captured alphabet
     * makes the source TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = prodpad_fail(&owned_error, "cannot create Prodpad finding");
        if (rc == 0 && verify) {
            /* Fixed valid URL: nil context is the constructor's ordinary drop.
             * It happens before either header and is not a false-kept finding. */
            if (!ctx) { br_result_clear(&result); continue; }
            rc = prodpad_verify(ctx, key, &result.verified, &owned_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = prodpad_fail(&owned_error, "cannot append Prodpad finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        prodpad_fail(&owned_error, "cannot collect Prodpad tokens");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const prodpad_keywords[] = {"prodpad"};
static br_detector prodpad_detector = {
    .type = 842, .version = 0, .name = "Prodpad", .custom_name = "",
    .description = "Prodpad is a product management tool that helps teams plan and manage product development. Prodpad API keys can be used to access and modify product data and configurations.",
    .keywords = prodpad_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = prodpad_scan,
};

int br_prodpad_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return prodpad_fail(error, "invalid Prodpad detector output");
    *out = NULL;
    if (!prodpad_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(prodpad_keywords, 1, "\\b([a-f0-9]{64})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        prodpad_detector.state = pattern;
    }
    *out = &prodpad_detector;
    return 0;
}
