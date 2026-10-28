/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flightstats/flightstats.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } flightstats_patterns;

static int flightstats_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor/read-error continue: DROP this pair, never
 * an ordinary false finding. Shared send errors instead KEEP the false finding. */
static bool flightstats_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result)
{
    static const char prefix[] = "https://api.flightstats.com/flex/aircraft/rest/v1/json/availableFields?appId=";
    static const char middle[] = "&appKey=";
    char url[126];
    _Static_assert(sizeof(prefix) - 1 + 8 + sizeof(middle) - 1 + 32 + 1 == sizeof(url),
                   "Flightstats URL: 125 bytes plus NUL");
    /* Finding and COMPLETE URL precede constructor handling. Bounds follow the
     * exact captures; no formatter, encoder, heap-copy seam or extra local cap. */
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at); memcpy(url + at, id.data, id.len); at += id.len;
    memcpy(url + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(url + at, key.data, key.len); at += key.len; url[at] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL; bool keep = true;
    /* WHOLE mixed shared setup/allocation/Do domain suppressed, false KEPT;
     * a populated body_error on a FAILED send must not become a read DROP. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        /* Source ReadAll precedes EVERY status, and even an EMPTY non-NULL
         * reader error DROPS the pair before otherwise-valid status/markers. */
        if (response.body_error != NULL) keep = false;
        else {
            const br_slice id_marker = {(const unsigned char *)"id", 2};
            const br_slice inactive = {(const unsigned char *)"application is not active", sizeof("application is not active") - 1};
            result->verified = (response.status >= 200 && response.status < 300 &&
                               br_slice_find(response.body, id_marker, 0) != SIZE_MAX) ||
                              (response.status == 403 && br_slice_find(response.body, inactive, 0) != SIZE_MAX);
        }
    }
    /* Binary substring search, never JSON/UTF-8/C-string/case normalization:
     * "invalid" contains "id", and NUL bytes do not terminate either search.
     * Full stack URL survives send AND release, including DROP/send failures.
     * Source scan-defers Close-only. Eager release/full Reader/native/private-
     * client/error-chain/regexp and global engine/output parity remain partial;
     * native HTTP guards are unchanged. No verification-error setter/classifier. */
    br_http_release(ctx, &response);
    free(transport_error);
    return keep;
}

static int flightstats_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flightstats_fail(error, "invalid or uninitialized Flightstats scan");
    const flightstats_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return flightstats_fail(error, "uninitialized Flightstats patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Original key-major OCCURRENCE products: no uniqueness, success break,
     * equality skip or local span check. Required ID remains HIDDEN even on
     * success. TrimSpace is a no-op; 1024 is only the inherited ENGINE HINT. */
    for (size_t k = 0; !rc && k < keys.len; ++k) for (size_t i = 0; !rc && i < ids.len; ++i) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, k), id = br_captures_at(&ids, i);
        /* Owned finding failure is fatal BEFORE constructor skip/read DROP or
         * shared-send suppression. Push failure is likewise fatal, not hidden. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = flightstats_fail(&owned_error, "cannot create Flightstats finding");
        if (!rc && verify) keep = flightstats_verify(ctx, key, id, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = flightstats_fail(&owned_error, "cannot append Flightstats finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&ids);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static flightstats_patterns flightstats_compiled;
static const char *const flightstats_keywords[] = {"flightstats"};
static const br_detector flightstats_detector = {
    .type = 642, .version = 0, .name = "Flightstats", .custom_name = "",
    .description = "Flightstats provides APIs for accessing flight data and statistics. Flightstats API keys can be used to retrieve and manipulate flight-related information.",
    .keywords = flightstats_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &flightstats_compiled, .scan = flightstats_scan,
};

int br_flightstats_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flightstats_fail(error, "invalid Flightstats detector output");
    *out = NULL;
    if (!flightstats_compiled.key) {
        br_regex *key = NULL, *id = NULL;
        /* Independent keyword-only CI prefixes; captures are LOWER ALNUM,
         * neither hex validation nor globally case-folded patterns. */
        int rc = br_regex_compile_prefixed(flightstats_keywords, 1, "\\b([0-9a-z]{32})\\b", &key, error);
        if (!rc) rc = br_regex_compile_prefixed(flightstats_keywords, 1, "\\b([0-9a-z]{8})\\b", &id, error);
        if (rc) { br_regex_free(key); br_regex_free(id); return -1; }
        flightstats_compiled = (flightstats_patterns){key, id};
    }
    *out = &flightstats_detector;
    return 0;
}
