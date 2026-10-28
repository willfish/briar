/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/freshbooks/freshbooks.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *uri; } freshbooks_patterns;

static int freshbooks_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int freshbooks_verify(const br_scan_ctx *ctx, br_slice key, br_slice uri,
                             br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://auth.freshbooks.com/oauth/authorize?client_id=";
    static const char middle[] = "&redirect_uri=", suffix[] = "&response_type=code";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(middle) - 1 + sizeof(suffix);
    _Static_assert(sizeof(prefix) - 1 == 54 && sizeof(middle) - 1 == 14 && sizeof(suffix) - 1 == 19,
                   "Freshbooks URL pieces must preserve literal query order");
    /* URI middle is unbounded; copy ONE complete URL, including interior NULs,
     * BEFORE every constructor/ABI guard. Private keys are 64 ASCII bytes. */
    if (key.len > SIZE_MAX - fixed || uri.len > SIZE_MAX - fixed - key.len)
        return freshbooks_fail(error, "Freshbooks URL size overflow");
    size_t size = fixed + key.len + uri.len;
    char *url = malloc(size);
    if (!url) return freshbooks_fail(error, "cannot allocate Freshbooks URL");
    size_t at = 0;
    memcpy(url + at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(url + at, key.data, key.len); at += key.len;
    memcpy(url + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(url + at, uri.data, uri.len); at += uri.len;
    memcpy(url + at, suffix, sizeof(suffix));
    int rc = 0;
    if (!ctx) { *keep = false; goto done; } /* Source constructor SKIP. */

    /* Pinned Go 1.26.7 net/url.Parse splits the FIRST '#' before checking C0/
     * DEL. Query '%' and SPACE/Unicode are not constructor errors. The captured
     * URI is opaque raw query, NOT an authority to normalize or validate. */
    const unsigned char *bytes = (const unsigned char *)url;
    const unsigned char *hash = memchr(bytes, '#', size - 1);
    size_t before = hash ? (size_t)(hash - bytes) : size - 1;
    for (size_t i = 0; i < before; ++i) {
        if (bytes[i] < 0x20 || bytes[i] == 0x7f) { *keep = false; goto done; }
    }
    if (hash) {
        size_t remaining = size - 1 - (size_t)(hash + 1 - bytes);
        /* In THIS grammar a fragment '%' can only be wildcard two, after '#'
         * at wildcard one: literal '%com' has invalid escape '%co'. No decoder. */
        if (memchr(hash + 1, '%', remaining)) { *keep = false; goto done; }
        if (memchr(hash + 1, '\0', remaining)) {
            rc = freshbooks_fail(error, "unsupported: Freshbooks embedded NUL in URL fragment");
            goto done; /* Go accepts it, but ABI1's URL C string cannot. */
        }
    }
    {
        const br_http_request request = {
            .method = "GET", .url = url, .profile = BR_HTTP_DETECTOR_PUBLIC,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Suppress the WHOLE mixed setup/allocation/Do domain as false-KEPT,
         * including unusable responses carrying body_error. No classifier. */
        if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
            /* ReadAll precedes EVERY status decision; ANY non-NULL cause,
             * including empty text, DROPS this pair rather than retaining it. */
            if (response.body_error) *keep = false;
            else {
                static const unsigned char marker[] = "Log In to FreshBooks";
                result->verified = response.status >= 200 && response.status < 300 &&
                    br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            }
        }
        /* Keep the SAME complete URL through synchronous send AND release.
         * PUBLIC/10s native no-local-IP support stays fail-closed, never SANE.
         * Source scan-defers Close after successful Do; eager Reader/release,
         * full native/public client, RE2 and global engine/output remain partial. */
        br_http_release(ctx, &response);
        free(transport_error);
    }
done:
    free(url);
    return rc == 0 ? 0 : -1;
}

static int freshbooks_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return freshbooks_fail(error, "invalid or uninitialized Freshbooks scan");
    const freshbooks_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, uris = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->uri, input, &uris, false, &owned_error);
    /* KEY-major ORIGINAL occurrence products. URI is required but HIDDEN,
     * even when verified. TrimSpace is a no-op for both capture grammars. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t u = 0; rc == 0 && u < uris.len; ++u) {
            br_result result = {0};
            bool keep = true;
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = freshbooks_fail(&owned_error, "cannot create Freshbooks result");
            if (rc == 0 && verify)
                rc = freshbooks_verify(ctx, key, br_captures_at(&uris, u), &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = freshbooks_fail(&owned_error, "cannot append Freshbooks result");
            br_result_clear(&result);
            /* No sets, equality skip, success break, local span cap or cache.
             * NoV never allocates URLs or applies constructor/ABI guards. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&uris);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const freshbooks_keywords[] = {"freshbooks"};
static freshbooks_patterns freshbooks_state;
static br_detector freshbooks_detector = {
    .type = 681, .version = 0, .name = "Freshbooks", .custom_name = "",
    .description = "FreshBooks is an accounting software package developed and marketed by 2ndSite Inc. FreshBooks API keys can be used to access and modify accounting data and perform other operations.",
    .keywords = freshbooks_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = freshbooks_scan,
};

int br_freshbooks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return freshbooks_fail(error, "invalid Freshbooks detector output");
    *out = NULL;
    if (!freshbooks_detector.state) {
        freshbooks_patterns patterns = {0};
        if (br_regex_compile_prefixed(freshbooks_keywords, 1, "\\b([0-9a-z]{64})\\b", &patterns.key, error) != 0 ||
            br_regex_compile_prefixed(freshbooks_keywords, 1, "\\b(https://www.[0-9A-Za-z_-]{1,}.com)\\b", &patterns.uri, error) != 0) {
            br_regex_free(patterns.key); br_regex_free(patterns.uri);
            return -1;
        }
        freshbooks_state = patterns;
        freshbooks_detector.state = &freshbooks_state;
    }
    *out = &freshbooks_detector;
    return 0;
}
