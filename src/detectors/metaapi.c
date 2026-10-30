/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/metaapi/metaapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *spell; } metaapi_patterns;

static int metaapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int metaapi_verify(const br_scan_ctx *ctx, br_slice key, br_slice spell,
                          br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://api.meta-api.io/api/spells/";
    static const char suffix[] = "/runSync";
    char url[sizeof(prefix) - 1 + 24 + sizeof(suffix)];
    /* Finding and full literal URL precede the nil-context constructor skip. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, spell.data, spell.len);
    memcpy(url + sizeof(prefix) - 1 + spell.len, suffix, sizeof(suffix));
    if (!ctx) {
        *keep = false;
        return 0;
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Apikey", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* Suppress the whole mixed preparation/Do nonzero domain without examining
     * a populated response or classifying its diagnostic text. No setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && response.body_error == NULL) {
        /* ReadAll precedes status at every status. Any non-NULL read error keeps
         * this finding false, even with completed matching bytes; it never drops. */
        if (!response.body.data && response.body.len)
            rc = metaapi_fail(error, "invalid MetaAPI response body slice");
        else {
            static const unsigned char marker[] = "\"success\":true";
            result->verified = response.status >= 200 && response.status < 300 &&
                br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Original URL/key/spell/headers survive exactly one release per attempted
     * send, including preparation failure. Synthesized prepared storage ends at
     * send return. ABI1 release differs from source scan-deferred Close timing. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int metaapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const metaapi_patterns *patterns = detector ? detector->state : NULL;
    if (!patterns || !patterns->key || !patterns->spell || !out || (!input.data && input.len))
        return metaapi_fail(error, "invalid or uninitialized MetaAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0}, spells = {0};
    char *owned_error = NULL;
    /* Both independent collections are source-ordered and duplicate-preserving.
     * Collect keys, then spells, even when the first collection is empty. */
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->spell, input, &spells, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < spells.len; ++i) {
        br_slice spell = br_captures_at(&spells, i);
        for (size_t j = 0; rc == 0 && j < keys.len; ++j) {
            br_slice key = br_captures_at(&keys, j);
            br_result result = {0};
            bool keep = true;
            /* TrimSpace is a no-op. Spell occurrences are outer, keys inner;
             * the 1024-byte engine hint is not a cap, even in NoV. Output key only. */
            if (key.len != 64 || spell.len != 24)
                rc = metaapi_fail(&owned_error, "invalid MetaAPI capture");
            else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = metaapi_fail(&owned_error, "cannot create MetaAPI finding");
            if (rc == 0 && verify) rc = metaapi_verify(ctx, key, spell, &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = metaapi_fail(&owned_error, "cannot append MetaAPI finding");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&spells);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const metaapi_keywords[] = {"metaapi", "meta-api"};
static metaapi_patterns metaapi_compiled;
static br_detector metaapi_detector = {
    .type = 737, .version = 0, .name = "MetaAPI", .custom_name = "",
    .description = "Detects MetaAPI credentials, which are typically API keys used for accessing the MetaAPI service.",
    .keywords = metaapi_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = metaapi_scan,
};

int br_metaapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return metaapi_fail(error, "invalid MetaAPI detector output");
    *out = NULL;
    if (!metaapi_detector.state) {
        br_regex *key = NULL, *spell = NULL;
        if (br_regex_compile_prefixed(metaapi_keywords, 2, "\\b([0-9a-f]{64})\\b", &key, error) != 0) {
            br_regex_free(key);
            return -1;
        }
        if (br_regex_compile_prefixed(metaapi_keywords, 2, "\\b([0-9a-f]{24})\\b", &spell, error) != 0) {
            br_regex_free(spell);
            br_regex_free(key);
            return -1;
        }
        metaapi_compiled = (metaapi_patterns){key, spell};
        metaapi_detector.state = &metaapi_compiled;
    }
    *out = &metaapi_detector;
    return 0;
}
