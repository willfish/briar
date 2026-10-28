/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/freshdesk/freshdesk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } freshdesk_patterns;

static int freshdesk_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int freshdesk_verify(const br_scan_ctx *ctx, br_slice key, br_slice host,
                             br_result *result, bool *keep, char **error)
{
    /* Source encodes TRUE Basic KEY:X BEFORE URL construction and constructor.
     * 22 ASCII bytes => 32 standard Base64 bytes, including two '='. */
    unsigned char credentials[22], encoded[33];
    memcpy(credentials, key.data, 20); credentials[20] = ':'; credentials[21] = 'X';
    if (EVP_EncodeBlock(encoded, credentials, sizeof(credentials)) != 32)
        return freshdesk_fail(error, "Freshdesk native Base64 encoding failed");
    encoded[32] = '\0';
    /* The direct captured host is UNBOUNDED. Only an arithmetic overflow guard,
     * no DNS normalization/assertions, local cap, VLA, formatter or extra copy. */
    if (host.len > SIZE_MAX - 24) return freshdesk_fail(error, "Freshdesk URL size overflow");
    char *url = malloc(host.len + 24);
    if (!url) return freshdesk_fail(error, "cannot allocate Freshdesk URL");
    memcpy(url, "https://", 8); memcpy(url + 8, host.data, host.len);
    memcpy(url + 8 + host.len, "/api/v2/tickets", 16); /* Complete suffix AND NUL. */
    if (!ctx) { free(url); *keep = false; return 0; }
    char authorization[39];
    memcpy(authorization, "Basic ", 6); memcpy(authorization + 6, encoded, sizeof(encoded));
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, no setter or
     * classifier. Every 2xx verifies; body/read errors are ignored. Own capture,
     * finding, encoding, URL and push failures are fatal OUTSIDE this domain. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete URL/auth/crypto buffers survive send AND release; free URL AFTER.
     * Source scan-defers Close: full Reader/deferred-close versus ABI1 buffering,
     * native URL/client/regexp and global source/engine/output parity remain
     * partial. Keep all shared guards intact; never live support-service checks. */
    br_http_release(ctx, &response);
    free(send_error); free(url);
    return 0;
}

static int freshdesk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return freshdesk_fail(error, "invalid or uninitialized Freshdesk scan");
    const freshdesk_patterns *patterns = detector->state;
    size_t original_len = out->len; br_captures keys = {0}, hosts = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->host, input, &hosts, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
            br_slice host = br_captures_at(&hosts, h); br_result result = {0}; bool keep = true;
            /* Original key-major occurrence products/duplicates, no sets/break/
             * equality skip/local engine span cap. TrimSpace is a no-op; required
             * host stays HIDDEN even verified. Finding precedes ALL preparation. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = freshdesk_fail(&owned_error, "cannot create Freshdesk result");
            if (rc == 0 && verify && freshdesk_verify(ctx, key, host, &result, &keep, &owned_error) != 0) rc = -1;
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = freshdesk_fail(&owned_error, "cannot append Freshdesk result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&hosts);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const freshdesk_keywords[] = {"freshdesk"};
static freshdesk_patterns freshdesk_state;
static br_detector freshdesk_detector = {
    .type = 678, .version = 0, .name = "Freshdesk", .custom_name = "",
    .description = "Freshdesk is a customer support software. Freshdesk API keys can be used to access and manage support tickets, contacts, and other customer support data.",
    .keywords = freshdesk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024, .scan = freshdesk_scan,
};

int br_freshdesk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return freshdesk_fail(error, "invalid Freshdesk detector output");
    *out = NULL;
    if (!freshdesk_detector.state) {
        br_regex *key = NULL, *host = NULL;
        if (br_regex_compile_prefixed(freshdesk_keywords, 1, "\\b([0-9A-Za-z]{20})\\b", &key, error) != 0) return -1;
        if (br_regex_compile("\\b([0-9a-z-]{1,}\\.freshdesk\\.com)\\b", &host, error) != 0) { br_regex_free(key); return -1; }
        freshdesk_state = (freshdesk_patterns){key, host}; freshdesk_detector.state = &freshdesk_state;
    }
    *out = &freshdesk_detector;
    return 0;
}
