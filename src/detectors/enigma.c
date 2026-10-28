/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/enigma/enigma.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int enigma_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static const char *enigma_content_type(const br_http_response *response)
{
    static const char name[] = "content-type";
    for (size_t h = 0; h < response->nheaders; ++h) {
        const char *candidate = response->headers[h].name;
        if (!candidate) continue;
        size_t i = 0;
        for (; name[i]; ++i) {
            unsigned char c = (unsigned char)candidate[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (unsigned char)name[i]) break;
        }
        if (!name[i] && !candidate[i])
            return response->headers[h].value ? response->headers[h].value : "";
    }
    return ""; /* Header.Get returns the FIRST value, including empty, or empty if missing. */
}

static char enigma_named_escape(unsigned char c)
{
    switch (c) {
    case '\a': return 'a'; case '\b': return 'b'; case '\f': return 'f';
    case '\n': return 'n'; case '\r': return 'r'; case '\t': return 't';
    case '\v': return 'v'; default: return '\0';
    }
}

static int enigma_content_type_cause(const char *value, char **cause, char **error)
{
    static const char prefix[] = "got HTTP 200 with unexpected Content-Type ";
    static const char hex[] = "0123456789abcdef";
    size_t size = sizeof(prefix) - 1 + 2 + 1; /* Prefix, two quotes, NUL. */
    *cause = NULL;
    /* ASCII subset of Go strconv.AppendQuote/appendEscapedRune, selected Go
     * e3336a22ad3f0a90bd252c95d8b5544e02674205. Existing Go BSD notices apply.
     * Check exact size in a first pass; no cap, truncation or temporary quote. */
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        unsigned char c = *p;
        if (c >= 0x80)
            return enigma_fail(error, "unsupported: Enigma non-ASCII Content-Type diagnostic requires Go quoting");
        size_t width = c == '"' || c == '\\' || enigma_named_escape(c) ? 2 : c < 0x20 || c == 0x7f ? 4 : 1;
        if (size > SIZE_MAX - width) return enigma_fail(error, "Enigma Content-Type cause size overflow");
        size += width;
    }
    char *text = malloc(size);
    if (!text) return enigma_fail(error, "cannot allocate Enigma Content-Type cause");
    size_t at = sizeof(prefix) - 1;
    memcpy(text, prefix, at); text[at++] = '"';
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        unsigned char c = *p; char escape = enigma_named_escape(c);
        if (c == '"' || c == '\\' || escape) {
            text[at++] = '\\'; text[at++] = escape ? escape : (char)c;
        } else if (c < 0x20 || c == 0x7f) {
            text[at++] = '\\'; text[at++] = 'x'; text[at++] = hex[c >> 4]; text[at++] = hex[c & 15];
        } else text[at++] = (char)c;
    }
    text[at++] = '"'; text[at] = '\0';
    *cause = text;
    return 0;
}

static int enigma_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Literal 26-byte GraphQL body is prepared BEFORE the constructor. No heap
     * body copy/formatter seam; static bytes remain valid through release. */
    static const unsigned char payload[] = "{\"query\":\"{ __typename }\"}";
    const br_slice body = {payload, sizeof(payload) - 1};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &key, 1) != 0)
            return enigma_fail(error, "cannot set Enigma verification error");
        return 0; /* Retain the false constructor-error finding, never skip. */
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"x-api-key", (const char *)key.data}, /* Borrow the complete owned capture. */
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.enigma.com/graphql",
        .headers = headers, .nheaders = 2, .body = body,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *quoted_cause = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* Retain the whole mixed shared setup/allocation/Do domain, with no text
     * classifier. Response body/read/drain errors never affect status policy. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) {
        const char *content_type = enigma_content_type(&response);
        /* FIRST check the exact substring. Even non-ASCII headers may verify;
         * the explicit unsupported boundary belongs ONLY to wrong-200 quoting. */
        if (strstr(content_type, "application/json")) result->verified = true;
        else { rc = enigma_content_type_cause(content_type, &quoted_cause, error); cause = quoted_cause; }
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = enigma_fail(error, "cannot format Enigma verification status");
        else cause = status_error;
    }
    /* Quote BEFORE token-only redaction, copying all causes before release.
     * NULL cause is a no-op; setter +1 and any owned formatter failure are fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = enigma_fail(error, "cannot set Enigma verification error");
    /* Source defers drain+close. ABI1 buffers/releases eagerly, even on error;
     * header NUL cannot be represented by its C strings. Non-ASCII diagnostic
     * quoting, full Reader/native POST redirects/client/regexp and global
     * source/engine/output parity remain partial. Keep native guards unchanged. */
    br_http_release(ctx, &response);
    free(send_error); free(quoted_cause);
    return rc == 0 ? 0 : -1;
}

static int enigma_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return enigma_fail(error, "invalid or uninitialized Enigma scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates,
         * without token validation, local filtering, cache or invented metadata. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = enigma_fail(&owned_error, "cannot create Enigma result");
        if (rc == 0 && verify && enigma_verify(ctx, key, &result, &owned_error) != 0) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = enigma_fail(&owned_error, "cannot append Enigma result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const enigma_keywords[] = {"enigma"};
static br_detector enigma_detector = {
    .type = 405, .version = 0, .name = "Enigma", .custom_name = "",
    .description = "Enigma is a business data intelligence platform. Enigma API keys grant access to comprehensive firmographic, legal, and identity datasets.",
    .keywords = enigma_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = enigma_scan,
};

int br_enigma_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return enigma_fail(error, "invalid Enigma detector output");
    *out = NULL;
    if (br_key_pattern_init(&enigma_detector, "\\b([a-zA-Z0-9]{40})\\b", error) != 0) return -1;
    *out = &enigma_detector;
    return 0;
}
