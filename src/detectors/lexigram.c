/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lexigram/lexigram.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

static int lexigram_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Go strings.TrimSpace, private to this pair. Invalid UTF-8 is RuneError:
 * not space, retained, and not a scan error. */
static br_slice lexigram_trim(br_slice capture)
{
    size_t begin = 0;
    while (begin < capture.len) {
        uint32_t rune = 0;
        size_t width = br_utf8_rune((br_slice){capture.data + begin, capture.len - begin}, &rune);
        if (!width || !(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        begin += width;
    }
    size_t end = begin;
    for (size_t at = begin; at < capture.len;) {
        uint32_t rune = 0;
        size_t width = br_utf8_rune((br_slice){capture.data + at, capture.len - at}, &rune);
        if (!width) {
            end = at + 1;
            at += 1;
            continue;
        }
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at + width;
        at += width;
    }
    return (br_slice){capture.data + begin, end - begin};
}

/* Successful Do only. The stack header array dies at send return. This node
 * keeps the owned Bearer through its own release, then frees it. */
typedef struct lexigram_pending lexigram_pending;
struct lexigram_pending {
    lexigram_pending *next;
    br_http_response response;
    char *authorization;
};

/* After this attempt's release, the Bearer must not remain readable. */
static void lexigram_forget_authorization(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void lexigram_drain(const br_scan_ctx *ctx, lexigram_pending *pending)
{
    while (pending) {
        lexigram_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        lexigram_forget_authorization(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET.
 * The Go client field is a test seam; verification uses the scan transport. */
static int lexigram_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, lexigram_pending **pending, char **error)
{
    static const char url[] = "https://api.lexigram.io/v1/lexigraph/search?q=diabetes";
    *keep = false;
    /* Drop after the finding exists. No Bearer, send, release, or setter. */
    if (!ctx) return 0;
    /* Construct the complete Bearer before the NUL boundary. An allocation
     * failure is fatal even when a NUL would otherwise publish unverified. */
    if (key.len > SIZE_MAX - 8)
        return lexigram_fail(error, "cannot allocate Lexigram authorization");
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) return lexigram_fail(error, "cannot allocate Lexigram authorization");
    memcpy(authorization, "Bearer ", 7);
    if (key.len) memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    /* ABI1 headers are C strings. Free the owned value and publish the
     * untruncated key unverified. This is not an attempted send. */
    if (key.len && memchr(key.data, '\0', key.len)) {
        free(authorization);
        *keep = true;
        return 0;
    }
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it. */
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    free(transport_error);
    if (send_rc != 0) {
        /* Do failed: no source defer. Release once now, while this Bearer is
         * still intact, then free it. The whole mixed send domain stays
         * unverified, with no setter and no retained response. */
        br_http_release(ctx, &response);
        lexigram_forget_authorization(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source defers Body.Close until FromData
     * returns, after append, last success first. */
    lexigram_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) {
        br_http_release(ctx, &response);
        lexigram_forget_authorization(authorization);
        lexigram_drain(ctx, *pending);
        *pending = NULL;
        return lexigram_fail(error, "cannot retain Lexigram response");
    }
    *attempt = (lexigram_pending){.next = *pending, .response = response,
                                  .authorization = authorization};
    *pending = attempt;
    /* Body and read errors are ignored and must not drop the finding. */
    if (response.status >= 200 && response.status < 300) result->verified = true;
    *keep = true;
    return 0;
}

static int lexigram_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lexigram_fail(error, "invalid or uninitialized Lexigram scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lexigram_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * Keep every occurrence, including duplicates, in match order. The finding
     * and request use the trimmed bytes, even when shorter or empty. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = lexigram_trim(br_captures_at(&keys, i));
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lexigram_fail(&owned_error, "cannot create Lexigram finding");
        if (!rc && verify)
            rc = lexigram_verify(ctx, key, &result, &keep, &pending, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = lexigram_fail(&owned_error, "cannot append Lexigram finding");
        br_result_clear(&result);
    }
    /* LIFO after publication, including retention and push failures.
     * Each successful send is released once here. Failed sends already released. */
    lexigram_drain(ctx, pending);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const lexigram_keywords[] = {"lexigram"};
static br_detector lexigram_detector = {
    .type = 437, .version = 0, .name = "Lexigram", .custom_name = "",
    .description = "Lexigram is a healthcare data service that provides an API for medical terminology and data. Lexigram API keys can be used to access and retrieve medical data.",
    .keywords = lexigram_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lexigram_scan,
};

int br_lexigram_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lexigram_fail(error, "invalid Lexigram detector output");
    *out = NULL;
    /* Pinned RE2 \S excludes only HT, LF, FF, CR, and space, so VT matches.
     * PCRE2 \S also excludes VT. This class is the same RE2 set. UTF mode
     * counts 301 runes, and word boundaries stay ASCII. */
    if (br_key_pattern_init(&lexigram_detector, "\\b([^\\t\\n\\f\\r ]{301})\\b", error) != 0)
        return -1;
    *out = &lexigram_detector;
    return 0;
}
