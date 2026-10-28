/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geocodio/geocodio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *search; } geocodio_patterns;

static int geocodio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int geocodio_trim(br_slice capture, br_slice *trimmed, char **error)
{
    size_t begin = 0, end = 0;
    for (size_t at = 0; at < capture.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){capture.data + at, capture.len - at}, &rune);
        if (!width) return geocodio_fail(error, "cannot decode Geocodio capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at + width;
        else if (at == begin) begin += width;
        at += width;
    }
    if (end < begin) end = begin;
    *trimmed = (br_slice){capture.data + begin, end - begin};
    return 0;
}

static int geocodio_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool geocodio_fragment_safe(unsigned char c)
{
    /* Go 1.26.7 encoding_table.go, encodeFragment, NOT QueryEscape. */
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || (c && strchr("!$&()*+,-./:;=?@_~", c));
}

static bool geocodio_raw_fragment_safe(unsigned char c)
{
    /* url.validEncoded additionally admits these bytes, including apostrophe
     * and brackets that canonical fragment escaping would percent-encode. */
    return geocodio_fragment_safe(c) || (c && strchr("'[]%", c));
}

static const char geocodio_url_prefix[] = "https://api.geocod.io/v1.6/geocode?q=";
static const char geocodio_url_join[] = "&api_key=";
enum {
    /* Search: <=30 valid UTF-8 runes, <=4 bytes each. Key: 39 ASCII bytes.
     * Every input byte expands by at most three in a projected fragment. */
    GEOCODIO_LITERAL_SIZE = sizeof(geocodio_url_prefix) - 1 + 30 * 4 +
                            sizeof(geocodio_url_join) - 1 + 39 + 1,
    GEOCODIO_URL_SIZE = 3 * (GEOCODIO_LITERAL_SIZE - 1) + 1,
};

static int geocodio_url(const br_scan_ctx *ctx, br_slice key, br_slice search,
                       char projected[GEOCODIO_URL_SIZE], bool *keep, char **error)
{
    if (key.len > 39 || search.len > 30 * 4)
        return geocodio_fail(error, "invalid Geocodio capture bounds");
    char literal[GEOCODIO_LITERAL_SIZE];
    size_t len = sizeof(geocodio_url_prefix) - 1;
    memcpy(literal, geocodio_url_prefix, len);
    memcpy(literal + len, search.data, search.len); len += search.len;
    memcpy(literal + len, geocodio_url_join, sizeof(geocodio_url_join) - 1);
    len += sizeof(geocodio_url_join) - 1;
    memcpy(literal + len, key.data, key.len); len += key.len;
    literal[len] = '\0';
    /* Source constructs the complete literal before NewRequestWithContext;
     * that constructor rejects nil ctx BEFORE parsing. No partial C strings. */
    if (!ctx) { *keep = false; return 0; }
    size_t hash = 0;
    while (hash < len && literal[hash] != '#') ++hash;
    /* url.Parse splits FIRST '#', then checks C0/DEL only before it. RawQuery
     * percent sequences are deliberately unvalidated, with no host heuristic. */
    for (size_t i = 0; i < hash; ++i) {
        unsigned char c = (unsigned char)literal[i];
        if (c < 32 || c == 127) { *keep = false; return 0; }
    }
    memcpy(projected, literal, hash);
    size_t out = hash;
    if (hash < len) {
        bool raw_valid = true;
        for (size_t i = hash + 1; i < len; ++i) {
            unsigned char c = (unsigned char)literal[i];
            if (c == '%' && (i + 2 >= len || geocodio_hex((unsigned char)literal[i + 1]) < 0 ||
                            geocodio_hex((unsigned char)literal[i + 2]) < 0)) {
                *keep = false;
                return 0;
            }
            if (!geocodio_raw_fragment_safe(c)) raw_valid = false;
        }
        projected[out++] = '#';
        if (raw_valid) {
            memcpy(projected + out, literal + hash + 1, len - hash - 1);
            out += len - hash - 1;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            /* setFragment unescapes first; EscapedFragment falls back to the
             * canonical table for the WHOLE decoded fragment if RawFragment
             * fails validEncoded. This also represents post-# NUL as %00. */
            for (size_t i = hash + 1; i < len; ++i) {
                unsigned char c = (unsigned char)literal[i];
                if (c == '%') {
                    c = (unsigned char)((geocodio_hex((unsigned char)literal[i + 1]) << 4) |
                                         geocodio_hex((unsigned char)literal[i + 2]));
                    i += 2;
                }
                if (geocodio_fragment_safe(c)) projected[out++] = (char)c;
                else {
                    projected[out++] = '%';
                    projected[out++] = hex[c >> 4];
                    projected[out++] = hex[c & 15];
                }
            }
        }
    }
    projected[out] = '\0';
    return 0;
}

static int geocodio_verify(const br_scan_ctx *ctx, br_slice key, br_slice search,
                          br_result *result, bool *keep, char **error)
{
    char url[GEOCODIO_URL_SIZE];
    int rc = geocodio_url(ctx, key, search, url, keep, error);
    if (rc != 0 || !*keep) return rc;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire mixed shared setup/allocation/Do failure domain.
     * No verification-error setter, retries, cache or body inspection. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack URL lives through send AND release, including failure.
     * Source defers Body.Close until scan return; ABI1 releases eagerly. The
     * projected URL is NewRequest's URL.String, not a claim about Go/curl wire
     * query/fragment handling, redirect or full SANE/runtime parity. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int geocodio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return geocodio_fail(error, "invalid or uninitialized Geocodio scan");
    const geocodio_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->search)
        return geocodio_fail(error, "uninitialized Geocodio patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, searches = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->search, input, &searches, false, &owned_error);
    /* Original occurrences, independent regex passes, key-major full product.
     * Search captures may overlap key captures; span1024 is an ENGINE hint. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = {0};
        if (geocodio_trim(br_captures_at(&keys, k), &key, &owned_error) != 0) rc = -1;
        for (size_t s = 0; rc == 0 && s < searches.len; ++s) {
            br_slice search = {0};
            br_result result = {0};
            bool keep = true;
            if (geocodio_trim(br_captures_at(&searches, s), &search, &owned_error) != 0) rc = -1;
            if (rc == 0 && br_finding_pair_bytes(&result, detector->type, key, "key",
                    search, "search_engine", (br_slice){0}) != 0)
                rc = geocodio_fail(&owned_error, "cannot create Geocodio result");
            if (rc == 0 && verify) rc = geocodio_verify(ctx, key, search, &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = geocodio_fail(&owned_error, "cannot append Geocodio result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&searches);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static geocodio_patterns geocodio_compiled;
static const char *const geocodio_keywords[] = {"geocod"};
static const br_detector geocodio_detector = {
    .type = 407, .version = 0, .name = "Geocodio", .custom_name = "",
    .description = "Geocodio is a service that provides geocoding and reverse geocoding. Geocodio API keys can be used to convert addresses into geographic coordinates and vice versa.",
    .keywords = geocodio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &geocodio_compiled, .scan = geocodio_scan,
};

int br_geocodio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return geocodio_fail(error, "invalid Geocodio detector output");
    *out = NULL;
    if (!geocodio_compiled.key && br_regex_compile_prefixed(geocodio_keywords, 1,
            "\\b([a-z0-9]{39})\\b", &geocodio_compiled.key, error) != 0) return -1;
    /* RE2 nonwhitespace excludes HT LF FF CR SPACE, but INCLUDES VT, Unicode
     * and NUL. Keep ASCII word boundaries and rune-counted greedy search. */
    if (!geocodio_compiled.search && br_regex_compile_prefixed(geocodio_keywords, 1,
            "\\b([^\\t\\n\\f\\r ]{7,30})\\b", &geocodio_compiled.search, error) != 0) return -1;
    *out = &geocodio_detector;
    return 0;
}
