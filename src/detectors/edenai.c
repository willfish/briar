/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/edenai/edenai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int edenai_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor-error continue, not a retained false result. */
static bool edenai_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* Constructor precedes header construction/validation. */
    /* ABI1 header values are C strings. Source Do rejects an embedded NUL and
     * suppresses that error: retain the COMPLETE false finding, with no I/O,
     * rather than truncate into an injected success. This is AFTER the ctor. */
    if (memchr(key.data, '\0', key.len)) return true;
    /* Two unescaped dots consume any valid rune except LF. All other capture
     * bytes are ASCII: max 179 raw bytes and 186 Bearer bytes plus NUL. No
     * JWT/Base64 validation, cap, heap auth copy or artificial format failure. */
    char authorization[187];
    _Static_assert(7 + 36 + 4 + 92 + 4 + 43 + 1 == sizeof(authorization), "EdenAI auth must fit 186 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.edenai.run/v1/automl/text/project",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Other controls use shared header validation. Suppress the ENTIRE mixed
     * shared setup/allocation/Do error domain; never classify diagnostic text,
     * call a verification-error setter, or skip these findings. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Stack auth stays live through BOTH send and release. Every body/read error
     * is ignored. Source scan-deferred Close-only timing, streaming Reader,
     * native/private-client, invalid-UTF-8 regexp and global engine/output
     * behavior remain partial; native HTTP guards stay unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int edenai_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return edenai_fail(error, "invalid or uninitialized EdenAI scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Capture edges are nonspace even when wildcard runes are whitespace/NUL:
     * TrimSpace is a no-op. Keep original byte lengths, order and duplicates. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = edenai_fail(&owned_error, "cannot create EdenAI finding");
        /* Own resources fail BEFORE the constructor skip or NUL/Do suppression. */
        if (!rc && verify) keep = edenai_verify(ctx, key, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = edenai_fail(&owned_error, "cannot append EdenAI finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const edenai_keywords[] = {"edenai"};
static br_detector edenai_detector = {
    .type = 568, .version = 0, .name = "EdenAI", .custom_name = "",
    .description = "EdenAI provides a unified API to access multiple AI engines. EdenAI API keys can be used to access and utilize these AI services.",
    .keywords = edenai_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = edenai_scan,
};

int br_edenai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return edenai_fail(error, "invalid EdenAI detector output");
    *out = NULL;
    /* WILDCARD dots are intentional. Only the keyword is case-insensitive;
     * the final class admits underscore, but NOT hyphen. This is not a JWT. */
    if (br_key_pattern_init(&edenai_detector, "\\b([a-zA-Z0-9]{36}.[a-zA-Z0-9]{92}.[a-zA-Z0-9_]{43})\\b", error) != 0) return -1;
    *out = &edenai_detector;
    return 0;
}
