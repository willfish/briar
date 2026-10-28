/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/faceplusplus/faceplusplus.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int faceplusplus_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes constructor skip, not verification rejection. All mixed
 * shared setup/allocation/Do failures retain this original false pair. */
static bool faceplusplus_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret, br_result *result)
{
    static const char base[] = "https://api-us.faceplusplus.com/facepp/v3/faceset/getfacesets?api_key=";
    static const char middle[] = "&api_secret=";
    /* Source completes the entire URL BEFORE construction. Each original
     * capture is exactly 32 unreserved ASCII bytes: no encoding, formatter,
     * heap copy or arbitrary cap. */
    char url[sizeof(base) - 1 + 32 + sizeof(middle) - 1 + 32 + 1];
    _Static_assert(sizeof(url) == 147, "FacePlusPlus URL is 146 bytes plus NUL");
    size_t at = sizeof(base) - 1;
    memcpy(url, base, at); memcpy(url + at, key.data, 32); at += 32;
    memcpy(url + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(url + at, secret.data, 32); url[at + 32] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Bodyless POST. Every 2xx verifies and every response body/read error,
     * even empty non-NULL, is ignored. Suppress the WHOLE mixed shared send
     * domain without a setter or diagnostic classifier, never a false skip. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack URL is live through synchronous send AND release. Source
     * scan-defers Close without reading; ABI1 eagerly buffers/releases even on
     * failure. Full Reader/deferred-close/native POST redirects/client/regexp
     * and global source/engine/output parity remain partial. Keep guards intact.
     * Acceptance must stay synthetic/injected, never live biometrics/provider. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int faceplusplus_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return faceplusplus_fail(error, "invalid or uninitialized FacePlusPlus scan");
    size_t original_len = out->len;
    br_captures credentials = {0}; char *owned_error = NULL;
    /* Identical role grammars have identical ORIGINAL occurrence lists. One
     * collection is sufficient, but NEVER make it unique or omit self-products. */
    int rc = br_captures_find(detector->state, input, &credentials, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < credentials.len; ++k) {
        br_slice key = br_captures_at(&credentials, k);
        for (size_t s = 0; rc == 0 && s < credentials.len; ++s) {
            br_slice secret = br_captures_at(&credentials, s);
            br_result result = {0}; bool keep = true;
            /* TrimSpace is a no-op. All N² key-major pairs, duplicates and
             * equal values included, get independent Raw/parts/RawV2 resources
             * BEFORE URL preparation/skip. Span 1024 is only an engine hint. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret", (br_slice){0}) != 0)
                rc = faceplusplus_fail(&owned_error, "cannot create FacePlusPlus result");
            if (rc == 0 && verify) keep = faceplusplus_verify(ctx, key, secret, &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = faceplusplus_fail(&owned_error, "cannot append FacePlusPlus result");
            br_result_clear(&result); /* A verified result NEVER breaks either product loop. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&credentials);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const faceplusplus_keywords[] = {"faceplusplus"};
static br_detector faceplusplus_detector = {
    .type = 416, .version = 0, .name = "FacePlusPlus", .custom_name = "",
    .description = "Face++ is a facial recognition service that provides APIs for detecting and analyzing faces. Face++ API keys and secrets can be used to access and manipulate these services.",
    .keywords = faceplusplus_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = faceplusplus_scan,
};

int br_faceplusplus_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return faceplusplus_fail(error, "invalid FacePlusPlus detector output");
    *out = NULL;
    if (br_key_pattern_init(&faceplusplus_detector, "\\b([0-9a-zA-Z_-]{32})\\b", error) != 0) return -1;
    *out = &faceplusplus_detector;
    return 0;
}
