/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hereapi/hereapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

static int hereapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int hereapi_trim(br_slice capture, br_slice *trimmed, char **error)
{
    size_t begin = 0, end = 0;
    for (size_t at = 0; at < capture.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){capture.data + at, capture.len - at}, &rune);
        if (!width) return hereapi_fail(error, "cannot decode HereAPI capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at + width;
        else if (at == begin) begin += width;
        at += width;
    }
    if (end < begin) end = begin;
    *trimmed = (br_slice){capture.data + begin, end - begin};
    return 0;
}

static int hereapi_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hereapi_fragment_safe(unsigned char c)
{
    /* Pinned Go 1.26.7 encodeFragment table, not QueryEscape. */
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || (c && strchr("!$&()*+,-./:;=?@_~", c));
}

static bool hereapi_raw_fragment_safe(unsigned char c)
{
    /* validEncoded also admits apostrophe, brackets and validated escapes. */
    return hereapi_fragment_safe(c) || (c && strchr("'[]%", c));
}

static const char hereapi_url_prefix[] =
    "https://weather.ls.hereapi.com/weather/1.0/report.json?product=alerts&name=Argentina&apiKey=";
enum {
    /* Exactly 43 valid UTF-8 runes in a capture, at most four bytes each.
     * Fragment projection expands each original byte by at most three. */
    HEREAPI_LITERAL_SIZE = sizeof(hereapi_url_prefix) - 1 + 43 * 4 + 1,
    HEREAPI_URL_SIZE = 3 * (HEREAPI_LITERAL_SIZE - 1) + 1,
};

static int hereapi_url(const br_scan_ctx *ctx, br_slice key,
                       char projected[HEREAPI_URL_SIZE], bool *keep, char **error)
{
    if (key.len > 43 * 4)
        return hereapi_fail(error, "invalid HereAPI capture bounds");
    char literal[HEREAPI_LITERAL_SIZE];
    size_t len = sizeof(hereapi_url_prefix) - 1;
    memcpy(literal, hereapi_url_prefix, len);
    memcpy(literal + len, key.data, key.len); len += key.len;
    literal[len] = '\0';
    /* fmt.Sprintf builds the entire literal before NewRequestWithContext;
     * nil context is a constructor drop before any URL parsing. */
    if (!ctx) { *keep = false; return 0; }
    size_t hash = 0;
    while (hash < len && literal[hash] != '#') ++hash;
    /* Parse splits FIRST '#', rejects C0/DEL only before it, and leaves
     * RawQuery percent sequences unvalidated. The fixed path/host are valid. */
    for (size_t i = 0; i < hash; ++i) {
        unsigned char c = (unsigned char)literal[i];
        if (c < 32 || c == 127) { *keep = false; return 0; }
    }
    memcpy(projected, literal, hash);
    size_t out = hash;
    /* Parse skips setFragment for empty frag; String omits a terminal '#'. */
    if (hash + 1 < len) {
        bool raw_valid = true;
        for (size_t i = hash + 1; i < len; ++i) {
            unsigned char c = (unsigned char)literal[i];
            if (c == '%' && (i + 2 >= len || hereapi_hex((unsigned char)literal[i + 1]) < 0 ||
                            hereapi_hex((unsigned char)literal[i + 2]) < 0)) {
                *keep = false;
                return 0;
            }
            if (!hereapi_raw_fragment_safe(c)) raw_valid = false;
        }
        projected[out++] = '#';
        if (raw_valid) {
            memcpy(projected + out, literal + hash + 1, len - hash - 1);
            out += len - hash - 1;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            /* setFragment unescapes first. If RawFragment is not validEncoded,
             * EscapedFragment canonically escapes the WHOLE decoded fragment,
             * including previously escaped bytes and post-hash NUL/controls. */
            for (size_t i = hash + 1; i < len; ++i) {
                unsigned char c = (unsigned char)literal[i];
                if (c == '%') {
                    c = (unsigned char)((hereapi_hex((unsigned char)literal[i + 1]) << 4) |
                                         hereapi_hex((unsigned char)literal[i + 2]));
                    i += 2;
                }
                if (hereapi_fragment_safe(c)) projected[out++] = (char)c;
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

static int hereapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                          bool *keep, char **error)
{
    char url[HEREAPI_URL_SIZE];
    int rc = hereapi_url(ctx, key, url, keep, error);
    if (rc != 0 || !*keep) return rc;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole mixed shared setup/Do failure domain keeps a false finding.
     * No setter, body reads, request coalescing or retry layer in this source. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* The original projected URL survives release, even after setup failure.
     * Ordinary synthesized headers/UA still end at send return. ABI1 releases
     * eagerly rather than source's deferred Close; URL.String projection does
     * not establish Go/curl wire, redirect or full SANE runtime parity. */
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int hereapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hereapi_fail(error, "invalid or uninitialized HereAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = {0};
        br_result result = {0};
        bool keep = true;
        /* Trim original rune bytes at BOTH ends before constructing a finding;
         * contextual boundaries can admit an entirely whitespace capture. */
        rc = hereapi_trim(br_captures_at(&keys, i), &key, &owned_error);
        if (rc == 0 && br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = hereapi_fail(&owned_error, "cannot create HereAPI finding");
        if (rc == 0 && verify) rc = hereapi_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = hereapi_fail(&owned_error, "cannot append HereAPI finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const hereapi_keywords[] = {"hereapi"};
static br_detector hereapi_detector = {
    .type = 408, .version = 0, .name = "HereAPI", .custom_name = "",
    .description = "HereAPI provides access to a wide range of location-based services including maps, geocoding, and traffic information. HereAPI keys can be used to authenticate and access these services.",
    .keywords = hereapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hereapi_scan,
};

int br_hereapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hereapi_fail(error, "invalid HereAPI detector output");
    *out = NULL;
    /* RE2 [a-zA-Z0-9\S] is exactly non-HT/LF/FF/CR/SPACE: VT, Unicode
     * and NUL are admitted. Keep ASCII word boundaries and 43 RUNE length. */
    if (br_key_pattern_init(&hereapi_detector, "\\b([^\\t\\n\\f\\r ]{43})\\b", error) != 0)
        return -1;
    *out = &hereapi_detector;
    return 0;
}
