/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bombbomb and common/patterns.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice trim_suffix(br_slice token)
{
    /* The capture starts with literal ey. Its final class excludes whitespace;
     * only the final wildcard with a zero-length third class can end in ONE
     * space rune. Independently encode Unicode White_Space membership facts,
     * not a copied Unicode data table or general TrimSpace implementation. */
    size_t n = token.len, width = 0;
    if (!n) return token;
    const unsigned char *s = token.data;
    unsigned char last = s[n - 1];
    if (last == ' ' || (last >= 0x09 && last <= 0x0d)) width = 1;
    else if (n >= 2 && s[n - 2] == 0xc2 && (last == 0x85 || last == 0xa0)) width = 2;
    else if (n >= 3) {
        unsigned char a = s[n - 3], b = s[n - 2];
        if ((a == 0xe1 && b == 0x9a && last == 0x80) || /* U+1680 */
            (a == 0xe2 && b == 0x80 &&
             ((last >= 0x80 && last <= 0x8a) || last == 0xa8 || last == 0xa9 || last == 0xaf)) ||
            (a == 0xe2 && b == 0x81 && last == 0x9f) || /* U+205F */
            (a == 0xe3 && b == 0x80 && last == 0x80))   /* U+3000 */
            width = 3;
    }
    token.len -= width;
    return token;
}

static int set_cause(br_result *result, const char *cause, char **error)
{
    /* Source supplies zero secret arguments: do not redact any error. */
    if (br_result_set_verification_error(result, cause, NULL, 0))
        return fail(error, "cannot store BombBomb verification error");
    return 0;
}

static int verify_bombbomb(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    /* The source constructs its fixed-URL request before adding Authorization. */
    if (!ctx) return set_cause(result, "net/http: nil Context", error);
    if (memchr(token.data, 0, token.len))
        return set_cause(result, "unsupported: BombBomb embedded NUL Authorization header", error);

    static const char bearer[] = "Bearer ";
    if (token.len > SIZE_MAX - sizeof(bearer)) return fail(error, "BombBomb Authorization header too large");
    char *auth = malloc(sizeof(bearer) + token.len);
    if (!auth) return fail(error, "cannot allocate BombBomb Authorization header");
    memcpy(auth, bearer, sizeof(bearer) - 1);
    if (token.len) memcpy(auth + sizeof(bearer) - 1, token.data, token.len);
    auth[sizeof(bearer) - 1 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.bombbomb.com/v2/user/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status == 200) {
        result->verified = true;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Shared pre-I/O header rejection handles non-NUL controls/DEL safely but
     * has a bounded Go Client.Do diagnostic-wording gap. HTAB and obs-text are
     * preserved. Body/drain/close errors are ignored on all status branches. */
    int rc = set_cause(result, cause, error);
    br_http_release(ctx, &response);
    free(transport_error); free(auth);
    return rc ? -1 : 0;
}

static int scan_bombbomb(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized BombBomb scan");
    br_captures captures = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    /* Preserve occurrences and opaque bytes. A const-char key verifier cannot
     * represent NUL captures or the shorter borrowed slice after TrimSpace. */
    int rc = br_captures_find(detector->state, input, &captures, false, &owned_error);
    for (size_t i = 0; !rc && i < captures.len; ++i) {
        br_slice token = trim_suffix(br_captures_at(&captures, i));
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key"))
            rc = fail(&owned_error, "cannot create BombBomb result");
        if (!rc && verify) rc = verify_bombbomb(ctx, token, &result, &owned_error);
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append BombBomb result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&captures);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"bombbomb"};
static br_detector bombbomb = {
    .type = 565, .version = 0, .name = "BombBomb", .custom_name = "",
    .description = "BombBomb is a video messaging platform that allows users to create and send video emails. BombBomb API keys can be used to access and manage video email campaigns and contacts.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bombbomb,
};

int br_bombbomb_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid BombBomb detector output");
    *out = NULL;
    /* Exact BuildRegexJWT expansion: wildcard dots, zero minima and ey (not
     * eyJ). Do not repair this into JWT validation or literal separators. */
    if (br_key_pattern_init(&bombbomb, "\\b(ey[0-9a-zA-Z]{0,140}.ey[0-9a-zA-Z-\\/_]{0,419}.[0-9a-zA-Z-\\/_]{0,171})\\b", error)) return -1;
    *out = &bombbomb;
    return 0;
}
