/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hive/hive.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *key; } hive_patterns;

static int hive_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int hive_verify(const br_scan_ctx *ctx, br_slice id, br_slice key,
                       br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://app.hive.com/api/v1/testcredentials?user_id=";
    static const char middle[] = "&api_key=";
    /* Both captures are fixed-size ASCII alphanumerics. Build the complete
     * literal query before the source's nil-context constructor drop. */
    size_t size = sizeof(prefix) - 1 + id.len + sizeof(middle) - 1 + key.len + 1;
    char *url = malloc(size);
    if (!url) return hive_fail(error, "cannot allocate Hive URL");
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, id.data, id.len); at += id.len;
    memcpy(url + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(url + at, key.data, key.len); at += key.len;
    url[at] = '\0';
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/Do failure domain is false-kept, without a
     * verification-error setter. No response body or read error is consumed. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original URL and captures survive release, including failed sends.
     * Ordinary ABI1 synthesized headers/UA end at send return. Source instead
     * scan-defers Close; this eager release does not establish that lifetime. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return 0;
}

static int hive_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hive_fail(error, "invalid or uninitialized Hive scan");
    const hive_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->key)
        return hive_fail(error, "uninitialized Hive patterns");
    size_t original_len = out->len;
    br_captures ids = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Independent original occurrences, ID-major full products, no dedup or
     * pair inequality. TrimSpace is a no-op on both capture grammars. */
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
            br_slice key = br_captures_at(&keys, k);
            br_result result = {0};
            bool keep = true;
            if (id.len != 17 || key.len != 32)
                rc = hive_fail(&owned_error, "invalid Hive capture");
            else if (br_finding_key_bytes(&result, detector->type, id, "key") != 0)
                rc = hive_fail(&owned_error, "cannot create Hive result");
            if (rc == 0 && verify)
                rc = hive_verify(ctx, id, key, &result, &keep, &owned_error);
            /* The actual API key is required but hidden; even SecretParts.key
             * is the ID. Do not invent RawV2, an ID part or a primary secret. */
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = hive_fail(&owned_error, "cannot append Hive result");
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

static hive_patterns hive_compiled;
static const char *const hive_keywords[] = {"hive"};
static const br_detector hive_detector = {
    .type = 571, .version = 0, .name = "Hive", .custom_name = "",
    .description = "Hive is a project management and collaboration tool. Hive API keys can be used to access and manage projects, tasks, and other data within a Hive workspace.",
    .keywords = hive_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &hive_compiled, .scan = hive_scan,
};

int br_hive_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hive_fail(error, "invalid Hive detector output");
    *out = NULL;
    if (!hive_compiled.id) {
        hive_patterns patterns = {0};
        if (br_regex_compile_prefixed(hive_keywords, 1, "\\b([0-9A-Za-z]{17})\\b", &patterns.id, error) != 0 ||
            br_regex_compile_prefixed(hive_keywords, 1, "\\b([0-9a-z]{32})\\b", &patterns.key, error) != 0) {
            br_regex_free(patterns.id);
            br_regex_free(patterns.key);
            return -1;
        }
        hive_compiled = patterns;
    }
    *out = &hive_detector;
    return 0;
}
