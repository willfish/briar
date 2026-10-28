/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/eightxeight/eightxeight.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } eightxeight_patterns;

static int eightxeight_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool eightxeight_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                               br_result *result)
{
    /* WARNING: this request sends an SMS to the source's fixed recipient and
     * can incur charges. Acceptance uses injected offline transports ONLY.
     * Source assigns client.Timeout=10s before preparing this literal Reader;
     * ABI1 selects 10000ms per request, not a global client mutation. */
    static const unsigned char body[] = "{\"source\":\"abcde\",\"destination\":\"+6512345678\",\"text\":\"Hello World!\",\"encoding\":\"AUTO\"}";
    static const char prefix[] = "https://sms.8x8.com/api/v1/subaccounts/", suffix[] = "/messages";
    char url[sizeof(prefix) - 1 + 30 + sizeof(suffix)];
    const size_t start = sizeof(prefix) - 1;
    _Static_assert(sizeof(url) == 79, "EightxEight maximum URL including NUL");
    /* The private ID pattern guarantees 18..30 URL-safe bytes. Build ONE
     * complete bounded URL before context-bound construction. */
    memcpy(url, prefix, start);
    memcpy(url + start, id.data, id.len);
    memcpy(url + start + id.len, suffix, sizeof(suffix));
    if (!ctx) return false; /* Known nil-context constructor failure skips this pair. */

    /* Header preparation follows successful construction. The fixed 43-byte
     * key fits Bearer's 50-byte value plus NUL; no heap copies or formatting. */
    char authorization[51];
    _Static_assert(sizeof("Bearer ") + 43 == sizeof(authorization), "EightxEight Bearer size");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = {body, sizeof(body) - 1}, .profile = BR_HTTP_SANE,
        .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain. There is no
     * verification-error setter or diagnostic classifier. Every 2xx verifies;
     * all response bodies/read errors are ignored, including empty causes. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* URL, complete Bearer and exact borrowed body remain live through BOTH
     * send and release. Source scan-defers Close only, without draining. Eager
     * buffering/release, streaming, persistent package-client timeout mutation/
     * races, native POST redirects (still fail-closed), full SANE/RE2 and global
     * engine/output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true; /* Keep the pair, including every suppressed send failure. */
}

static int eightxeight_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return eightxeight_fail(error, "invalid or uninitialized EightxEight scan");
    const eightxeight_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return eightxeight_fail(error, "uninitialized EightxEight patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent original occurrence lists, not sets. TrimSpace is a no-op.
     * Keep key-major full products, duplicates included, without equality,
     * local span/entropy checks or verified-pair breaks. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            br_slice id = br_captures_at(&ids, i);
            bool keep = true;
            /* Finding and RawV2 resources precede URL prep and constructor SKIP. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = eightxeight_fail(&owned_error, "cannot create EightxEight result");
            if (rc == 0 && verify)
                keep = eightxeight_verify(ctx, key, id, &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = eightxeight_fail(&owned_error, "cannot append EightxEight result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static eightxeight_patterns eightxeight_compiled;
static const char *const eightxeight_keywords[] = {"8x8"};
static const br_detector eightxeight_detector = {
    .type = 727, .version = 0, .name = "EightxEight", .custom_name = "",
    .description = "8x8 is a provider of cloud-based communication services including voice, video, chat, and contact center solutions.",
    .keywords = eightxeight_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &eightxeight_compiled, .scan = eightxeight_scan,
};

int br_eightxeight_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return eightxeight_fail(error, "invalid EightxEight detector output");
    *out = NULL;
    if (!eightxeight_compiled.key && br_regex_compile_prefixed(eightxeight_keywords, 1,
            "\\b([a-zA-Z0-9]{43})\\b", &eightxeight_compiled.key, error) != 0) return -1;
    if (!eightxeight_compiled.id && br_regex_compile_prefixed(eightxeight_keywords, 1,
            "\\b([a-zA-Z0-9_]{18,30})\\b", &eightxeight_compiled.id, error) != 0) return -1;
    *out = &eightxeight_detector;
    return 0;
}
