/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/envoyapikey/envoyapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int envoyapikey_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void envoyapikey_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Constructor's known nil-context skip precedes header preparation. Borrow
     * the complete owned 220-byte capture and NUL through send AND release. */
    const br_header headers[] = {
        {"Accept", "application/vnd.envoy+json; version=3"},
        {"X-Api-Key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.envoy.com/v1/locations",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, keeping a
     * false finding without a setter or diagnostic classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        static const unsigned char invalid[] = "\"status\":401";
        /* Source reads ALL bytes before EVERY status and intentionally ignores
         * the read error. Search partial binary bytes too: do NOT introduce a
         * body_error guard, JSON parser, case fold or whitespace normalization. */
        bool rejected = br_slice_find(response.body, (br_slice){invalid, sizeof(invalid) - 1}, 0) != SIZE_MAX;
        result->verified = ((response.status >= 200 && response.status < 300) || response.status == 403) && !rejected;
    }
    /* Source scan-defers Close only. Eager Reader/release timing, native/private
     * client, regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int envoyapikey_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return envoyapikey_fail(error, "invalid or uninitialized EnvoyApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve every original occurrence/duplicate;
         * owned finding resources precede the known constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = envoyapikey_fail(&owned_error, "cannot create EnvoyApiKey result");
        else if (!verify || ctx) {
            if (verify) envoyapikey_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = envoyapikey_fail(&owned_error, "cannot append EnvoyApiKey result");
        } /* Constructor skip without an artificial append/clear. */
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const envoyapikey_keywords[] = {"envoy"};
static br_detector envoyapikey_detector = {
    .type = 923, .version = 0, .name = "EnvoyApiKey", .custom_name = "",
    .description = "Envoy is a cloud-based platform that provides visitor management solutions. Envoy API keys can be used to access and manage visitor data and other resources within the Envoy platform.",
    .keywords = envoyapikey_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = envoyapikey_scan,
};

int br_envoyapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return envoyapikey_fail(error, "invalid EnvoyApiKey detector output");
    *out = NULL;
    if (br_key_pattern_init(&envoyapikey_detector, "\\b([a-zA-Z0-9]{220})\\b", error) != 0) return -1;
    *out = &envoyapikey_detector;
    return 0;
}
