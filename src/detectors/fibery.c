/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fibery/fibery.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } fibery_patterns;

static int fibery_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int fibery_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : fibery_fail(error, "cannot create Fibery verification cause");
}

static int fibery_verify(const br_scan_ctx *ctx, br_slice key, br_slice domain,
                         br_result *result, char **error)
{
    static const char suffix[] = ".fibery.io/api/commands";
    char url[95], authorization[51]; br_header headers[2];
    _Static_assert(8 + 63 + sizeof(suffix) == sizeof(url), "Fibery URL: 94 bytes plus NUL");
    _Static_assert(6 + 44 + 1 == sizeof(authorization), "Fibery Token: 50 bytes plus NUL");
    /* Exact pattern bounds, not an extra DNS/length/local-span policy. Prepare
     * the COMPLETE original-case URL after the finding, before constructor. */
    memcpy(url, "https://", 8);
    memcpy(url + 8, domain.data, domain.len);
    memcpy(url + 8 + domain.len, suffix, sizeof(suffix));
    br_http_response response = {0}; char *cause = NULL, *transport_error = NULL;
    bool sent = false; int rc = 0;
    if (!ctx) rc = fibery_cause(&cause, "net/http: nil Context", error); /* Retain, never skip. */
    else {
        /* Constructor precedes Content-Type, then the COMPLETE literal Token
         * header. Both bounded arrays survive synchronous send AND release. */
        headers[0] = (br_header){"Content-Type", "application/json"};
        memcpy(authorization, "Token ", 6);
        memcpy(authorization + 6, key.data, key.len);
        authorization[6 + key.len] = '\0';
        headers[1] = (br_header){"Authorization", authorization};
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000,
            .detector_type = result->detector_type,
            /* Source http.NoBody: logical bodyless POST, not {} or an empty reader. */
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
            /* Whole mixed shared setup/allocation/Do domain is RETAINED, not
             * classified by diagnostic text or converted to a fatal owned error. */
            cause = transport_error; transport_error = NULL;
            if (!cause) rc = fibery_cause(&cause, "HTTP transport failed", error);
        } else if (response.status == 200) result->verified = true;
        else if (response.status != 401) {
            char message[64]; int len = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            rc = len >= 0 && (size_t)len < sizeof(message) ? fibery_cause(&cause, message, error) :
                fibery_fail(error, "cannot format Fibery status cause");
        }
    }
    /* Exact source order SECRET then DOMAIN, even when one overlaps the other.
     * Copy/sanitize the cause before release; NULL is a no-op, ANY nonzero fatal. */
    const br_slice secrets[] = {key, domain};
    if (!rc && br_result_set_verification_error(result, cause, secrets, 2) != 0)
        rc = fibery_fail(error, "cannot sanitize Fibery verification error");
    /* Source verifier drains/closes and ignores every body/read/drain error.
     * Native PUBLIC and POST-redirect guards remain fail-closed: an injected
     * 200 does NOT prove native public-address/redirect support. Per-request 10s
     * is not source shared-client timeout mutation/race parity. Full Reader,
     * private-client/error-chain/regexp and global engine/output parity are partial. */
    if (sent) br_http_release(ctx, &response);
    free(cause); free(transport_error);
    return rc ? -1 : 0;
}

static int fibery_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fibery_fail(error, "invalid or uninitialized Fibery scan");
    const fibery_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->domain) return fibery_fail(error, "uninitialized Fibery patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->domain, input, &domains, true, &owned_error);
    /* Byte-unique key-major products, no verified break. Domain REQUIRED but
     * HIDDEN even on success. First-source traversal is not Go randomized map
     * order. The 1024 span is an ENGINE HINT, never a local distance limit. */
    for (size_t k = 0; !rc && k < keys.len; ++k) for (size_t d = 0; !rc && d < domains.len; ++d) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, k), domain = br_captures_at(&domains, d);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fibery_fail(&owned_error, "cannot create Fibery finding");
        if (!rc && verify) rc = fibery_verify(ctx, key, domain, &result, &owned_error);
        if (!rc && br_results_push(out, &result) != 0) rc = fibery_fail(&owned_error, "cannot append Fibery finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&domains);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static fibery_patterns fibery_compiled;
static const char *const fibery_keywords[] = {".fibery.io"};
static const char *const fibery_key_prefix[] = {"fibery"};
static const br_detector fibery_detector = {
    .type = 808, .version = 0, .name = "Fibery", .custom_name = "",
    .description = "Fibery is a work management platform that combines various tools for project management, knowledge management, and software development. Fibery API tokens can be used to access and modify data within a Fibery workspace.",
    .keywords = fibery_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &fibery_compiled, .scan = fibery_scan,
};

int br_fibery_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fibery_fail(error, "invalid Fibery detector output");
    *out = NULL;
    if (!fibery_compiled.key) {
        br_regex *key = NULL, *domain = NULL;
        /* Extraction prefix deliberately differs from the dispatch keyword. */
        int rc = br_regex_compile_prefixed(fibery_key_prefix, 1, "\\b([0-9a-f]{8}\\.[0-9a-f]{35})\\b", &key, error);
        /* Unanchored, case-sensitive literal suffix; no DNS validation, scheme
         * normalization or independent-domain search inside the GREEDY slash tail. */
        if (!rc) rc = br_regex_compile("(?:https?:\\/\\/)?([a-zA-Z0-9-]{1,63})\\.fibery\\.io(?:\\/.*)?", &domain, error);
        if (rc) { br_regex_free(key); br_regex_free(domain); return -1; }
        fibery_compiled = (fibery_patterns){key, domain};
    }
    *out = &fibery_detector;
    return 0;
}
