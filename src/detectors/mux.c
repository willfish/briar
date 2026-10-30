/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mux/mux.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } mux_patterns;

static int mux_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Go strings.TrimSpace, private to this pair. The secret capture's required
 * trailing space, CR, or LF is whitespace and must not reach the password. */
static br_slice mux_trim(br_slice capture)
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

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET. */
static int mux_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret,
                      br_result *result, bool *keep, char **error)
{
    static const char url[] = "https://api.mux.com/video/v1/assets";
    *keep = false;
    if (key.len != 36 || secret.len != 75) return mux_fail(error, "invalid Mux capture");
    if (!ctx) return 0;
    /* The helper already returns "Basic ". Keep it alive through send and
     * release, then free it. Do not add another prefix. */
    char *authorization = NULL;
    if (br_http_basic_auth(key, secret, &authorization, error) != 0) return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Preparation and Do stay unverified, with no setter. Source never reads
     * the body, so a body_error cannot suppress a 2xx or drop the finding.
     * Release once for every attempted send. */
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int mux_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mux_fail(error, "invalid or uninitialized Mux scan");
    const mux_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->secret)
        return mux_fail(error, "uninitialized Mux patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, false, &owned_error);
    /* br_scan_key cannot express a missing side or the constructor drop.
     * Either side alone yields nothing and no error. Keep every pair,
     * including duplicates, key-major and secret-minor. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_result result = {0};
            bool keep = true;
            br_slice key = br_captures_at(&keys, k);
            br_slice secret = mux_trim(br_captures_at(&secrets, s));
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret",
                                      (br_slice){0}) != 0)
                rc = mux_fail(&owned_error, "cannot create Mux finding");
            if (!rc && verify)
                rc = mux_verify(ctx, key, secret, &result, &keep, &owned_error);
            if (!rc && keep && br_results_push(out, &result) != 0)
                rc = mux_fail(&owned_error, "cannot append Mux finding");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const mux_keywords[] = {"mux"};
static mux_patterns mux_compiled;
static br_detector mux_detector = {
    .type = 748, .version = 0, .name = "Mux", .custom_name = "",
    .description = "Mux is a video streaming service that provides APIs for video hosting, live streaming, and video analytics. Mux API keys can be used to access and manage video assets and streaming data.",
    .keywords = mux_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &mux_compiled, .scan = mux_scan,
};

int br_mux_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mux_fail(error, "invalid Mux detector output");
    *out = NULL;
    if (!mux_compiled.key &&
        br_regex_compile_prefixed(mux_keywords, 1,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            &mux_compiled.key, error) != 0)
        return -1;
    if (!mux_compiled.secret &&
        br_regex_compile_prefixed(mux_keywords, 1,
            "([ \\r\\n]{0,1}[0-9A-Za-z\\/\\+]{75}[ \\r\\n]{1})",
            &mux_compiled.secret, error) != 0)
        return -1;
    *out = &mux_detector;
    return 0;
}
