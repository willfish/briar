/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/formcraft/formcraft.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int formcraft_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int formcraft_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            bool *keep, char **error)
{
    /* Source builds KEY + ':' and STANDARD Base64 BEFORE the constructor,
     * including nil-context skips. Fixed 16-byte capture: 17 input bytes, 24
     * encoded bytes (one '='), with no heap/formatter/cap/failure seam. */
    unsigned char credentials[17], encoded[25];
    _Static_assert(sizeof(credentials) == 16 + 1 && sizeof(encoded) == 24 + 1, "Formcraft Basic bounds");
    memcpy(credentials, key.data, 16); credentials[16] = ':';
    if (EVP_EncodeBlock(encoded, credentials, sizeof(credentials)) != 24)
        return formcraft_fail(error, "Formcraft native Base64 encoding failed");
    encoded[24] = '\0';
    if (!ctx) { *keep = false; return 0; }
    /* Header assembly follows successful constructor handling, unlike the
     * credential encoding above. TRUE Basic with an EMPTY password, not raw
     * key, KEY without colon, reversed credentials or a Bearer projection. */
    char authorization[31];
    _Static_assert(6 + 24 + 1 == sizeof(authorization), "Formcraft Basic: 30 bytes plus NUL");
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, encoded, sizeof(encoded));
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://formcrafts.com/api/v1/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* WHOLE mixed shared setup/allocation/Do domain suppresses to false KEPT,
     * without setter, diagnostic classifier or guard bypass. Native owned
     * capture/finding/encoding/append failures remain outside this domain. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack auth survives send AND release. Body/read errors ignored.
     * Source scan-defers Close-only; eager owned release/Reader, native/private-
     * client/error-chain/regexp and global engine/output parity remain partial.
     * Native HTTP guards are unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int formcraft_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return formcraft_fail(error, "invalid or uninitialized Formcraft scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        /* Original occurrences/duplicates; TrimSpace is a no-op. Finding
         * resources precede encoding, constructor skip and shared suppression. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = formcraft_fail(&owned_error, "cannot create Formcraft finding");
        if (!rc && verify && formcraft_verify(ctx, br_captures_at(&keys, i), &result, &keep, &owned_error) != 0)
            rc = -1;
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = formcraft_fail(&owned_error, "cannot append Formcraft finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const formcraft_keywords[] = {"formcraft"};
static br_detector formcraft_detector = {
    .type = 812, .version = 0, .name = "Formcraft", .custom_name = "",
    .description = "Formcraft is a form building and data collection service. Formcraft keys can be used to access and manage forms and collected data.",
    .keywords = formcraft_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = formcraft_scan,
};

int br_formcraft_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return formcraft_fail(error, "invalid Formcraft detector output");
    *out = NULL;
    /* Keyword-only CI. Capture is LOWER ALNUM, not hex or globally case-folded. */
    if (br_key_pattern_init(&formcraft_detector, "\\b([0-9a-z]{16})\\b", error) != 0) return -1;
    *out = &formcraft_detector;
    return 0;
}
