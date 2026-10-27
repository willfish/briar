/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/d7network/d7network.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

static int d7network_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int d7network_trim(br_slice capture, br_slice *key, char **error)
{
    size_t at = 0;
    /* The final literal '=' is nonspace, so Go TrimSpace can remove ONLY a
     * leading run. Inspect original runes with the pinned Go space property;
     * no locale, normalization or whole-input invalid-byte policy is added. */
    while (at < capture.len) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){capture.data + at, capture.len - at}, &rune);
        if (!width) return d7network_fail(error, "cannot decode D7Network capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        at += width;
    }
    *key = (br_slice){capture.data + at, capture.len - at};
    return 0;
}

static void d7network_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, bool *keep)
{
    /* The fixed URL/method leaves nil ctx as the known constructor failure.
     * Source skips this candidate BEFORE Authorization preparation. */
    if (!ctx) {
        *keep = false;
        return;
    }
    /* ABI1 headers are C strings. A full embedded-NUL finding is retained,
     * false with no error, without truncating or sending a different header.
     * Source Client.Do rejects this invalid header and suppresses that error. */
    if (memchr(key.data, '\0', key.len)) return;
    static const char basic[] = "Basic ";
    /* 23 valid runes (up to 4 bytes each) + '=' bounds a complete capture at
     * 93 bytes. Thus this exact grammar needs at most 99 header bytes + NUL,
     * not a 24-byte assumption, a new length cap, or an owned heap auth copy. */
    char authorization[sizeof(basic) + 23 * 4 + 1];
    memcpy(authorization, basic, sizeof(basic) - 1);
    memcpy(authorization + sizeof(basic) - 1, key.data, key.len);
    authorization[sizeof(basic) - 1 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://rest-api.d7networks.com/secure/balance",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_DETECTOR_PUBLIC,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE combined shared setup/allocation/Do error domain.
     * No error setter/classifier or Basic encoding/semantic validation. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Stack auth lives through send AND release. PUBLIC is not a SANE alias:
     * native curl must remain fail-closed before I/O, pending full public-IP
     * and redirect policy. Injected success does not establish that parity.
     * Source scan-defers Close only, ignoring body/read errors. Eager buffer/
     * release lifetime, full native client and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int d7network_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return d7network_fail(error, "invalid or uninitialized D7Network scan");
    size_t original_len = out->len;
    br_captures captures = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &captures, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < captures.len; ++i) {
        br_result result = {0};
        br_slice key = {0};
        bool keep = true;
        /* Keep occurrences even when distinct leading whitespace trims to the
         * same raw bytes. Finding resources precede constructor/NUL guards. */
        if (d7network_trim(br_captures_at(&captures, i), &key, &owned_error) != 0) rc = -1;
        if (rc == 0 && br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = d7network_fail(&owned_error, "cannot create D7Network result");
        if (rc == 0 && verify) d7network_verify(ctx, key, &result, &keep);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = d7network_fail(&owned_error, "cannot append D7Network result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&captures);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const d7network_keywords[] = {"d7network"};
static br_detector d7network_detector = {
    .type = 138, .version = 0, .name = "D7Network", .custom_name = "",
    .description = "D7Network provides messaging services through their API. The credentials can be used to send SMS and other types of messages via their platform.",
    .keywords = d7network_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = d7network_scan,
};

int br_d7network_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return d7network_fail(error, "invalid D7Network detector output");
    *out = NULL;
    /* The class union covers ALL valid runes, including NUL/newline/Unicode.
     * Keep the leading ASCII word boundary and the absence of an end boundary;
     * the shared RE2-subset invalid-byte barriers remain unchanged. */
    if (br_key_pattern_init(&d7network_detector, "\\b([a-zA-Z0-9\\W\\S]{23}\\=)", error) != 0)
        return -1;
    *out = &d7network_detector;
    return 0;
}
