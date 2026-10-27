/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dnscheck/dnscheck.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } dnscheck_patterns;

static int dnscheck_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void dnscheck_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                             br_result *result, bool *keep)
{
    static const char prefix[] = "https://www.dnscheck.co/api/v1/groups/", query[] = "?api_key=";
    /* Exact 36-byte ID and 32-byte key: the complete literal URL is 115 bytes
     * + NUL. Concatenate on the stack BEFORE the known constructor skip,
     * without a heap copy, format seam, UUID parsing or case normalization. */
    char url[sizeof(prefix) - 1 + 36 + sizeof(query) - 1 + 32 + 1];
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, id.data, id.len); at += id.len;
    memcpy(url + at, query, sizeof(query) - 1); at += sizeof(query) - 1;
    memcpy(url + at, key.data, key.len); at += key.len;
    url[at] = '\0';
    if (!ctx) {
        *keep = false; /* NewRequestWithContext(nil) skips this candidate only. */
        return;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 also mixes setup/allocation into
     * this domain: suppress it whole, with no setter or diagnostic classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack URL survives send AND release. Source scan-defers Close
     * only and ignores bodies/read errors. Eager buffering/release, full native
     * client, regexp and global source/engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int dnscheck_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dnscheck_fail(error, "invalid or uninitialized Dnscheck scan");
    const dnscheck_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return dnscheck_fail(error, "uninitialized Dnscheck patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* TrimSpace is a no-op for both grammars. Preserve original occurrence
     * order and duplicates in ALL key-major products, without local span,
     * UUID/hex validation, equality filters, consumption or caching. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            bool keep = true;
            br_slice id = br_captures_at(&ids, i);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = dnscheck_fail(&owned_error, "cannot create Dnscheck result");
            if (rc == 0 && verify) dnscheck_verify(ctx, key, id, &result, &keep);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = dnscheck_fail(&owned_error, "cannot append Dnscheck result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static dnscheck_patterns dnscheck_compiled;
static const char *const dnscheck_keywords[] = {"dnscheck"};
static const br_detector dnscheck_detector = {
    .type = 281, .version = 0, .name = "Dnscheck", .custom_name = "",
    .description = "Dnscheck is a service used to monitor DNS records. The API keys can be used to access and manage DNS monitoring configurations.",
    .keywords = dnscheck_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &dnscheck_compiled, .scan = dnscheck_scan,
};

int br_dnscheck_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dnscheck_fail(error, "invalid Dnscheck detector output");
    *out = NULL;
    if (!dnscheck_compiled.key) {
        dnscheck_patterns compiled = {0};
        if (br_regex_compile_prefixed(dnscheck_keywords, 1, "\\b([a-z0-9A-Z]{32})\\b", &compiled.key, error) != 0 ||
            br_regex_compile_prefixed(dnscheck_keywords, 1, "\\b([a-z0-9A-Z-]{36})\\b", &compiled.id, error) != 0) {
            br_regex_free(compiled.key);
            br_regex_free(compiled.id);
            return -1;
        }
        dnscheck_compiled = compiled;
    }
    *out = &dnscheck_detector;
    return 0;
}
