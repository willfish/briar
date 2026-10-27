/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloze/cloze.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } cloze_patterns;
typedef enum { CLOZE_ABORT = -1, CLOZE_KEEP = 0, CLOZE_SKIP = 1 } cloze_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool unreserved(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
}

/* One complete owned URL, not a temporary form plus another URL copy.
 * Positive 1 means resource/size failure, never the constructor-skip outcome. */
static int request_url(br_slice key, br_slice email, char **out)
{
    static const char prefix[] = "https://api.cloze.com/v1/profile?api_key=", user[] = "&user=";
    static const char hex[] = "0123456789ABCDEF";
    *out = NULL;
    size_t encoded = 0;
    for (size_t i = 0; i < email.len; ++i) {
        size_t width = unreserved(email.data[i]) || email.data[i] == ' ' ? 1 : 3;
        if (encoded > SIZE_MAX - width) return 1;
        encoded += width;
    }
    /* Captured key is exactly 32 lowercase hex bytes, already unreserved. */
    size_t fixed = sizeof(prefix) - 1 + key.len + sizeof(user) - 1;
    if (encoded > SIZE_MAX - fixed - 1) return 1;
    char *url = malloc(fixed + encoded + 1);
    if (!url) return 1;
    size_t at = 0;
    memcpy(url + at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(url + at, key.data, key.len); at += key.len;
    memcpy(url + at, user, sizeof(user) - 1); at += sizeof(user) - 1;
    /* url.Values.Encode sorts api_key before user. QueryEscape is byte-based,
     * preserving original email case/controls through uppercase percent bytes. */
    for (size_t i = 0; i < email.len; ++i) {
        unsigned char c = email.data[i];
        if (unreserved(c)) url[at++] = (char)c;
        else if (c == ' ') url[at++] = '+';
        else { url[at++] = '%'; url[at++] = hex[c >> 4]; url[at++] = hex[c & 15]; }
    }
    url[at] = '\0'; *out = url;
    return 0;
}

static cloze_outcome verify_cloze(const br_scan_ctx *ctx, br_slice key, br_slice email,
                                  br_result *result, char **error)
{
    char *url = NULL;
    /* Source payload.Encode happens BEFORE NewRequestWithContext. Do not
     * suppress URL-allocation +1 as a constructor skip or a Client.Do error. */
    if (request_url(key, email, &url)) { fail(error, "cannot construct Cloze request URL"); return CLOZE_ABORT; }
    if (!ctx) { free(url); return CLOZE_SKIP; }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* ALL Do errors retain false/nil findings. ABI1 also mixes adapter setup
     * and allocation errors here; no diagnostic-text stage classification. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY. Eager ABI1
     * release/full client configuration and global URL namespaces stay partial.
     * Keep the complete borrowed URL alive through synchronous send/release. */
    br_http_release(ctx, &response);
    free(transport_error); free(url);
    return CLOZE_KEEP;
}

static int scan_cloze(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Cloze scan");
    const cloze_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->email) return fail(error, "uninitialized Cloze patterns");
    br_captures keys = {0}, emails = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    /* Full capture 1, byte-unique/case-preserved. Both capture alphabets have
     * non-whitespace edges, so TrimSpace is a no-op, even for quoted controls. */
    if (!rc) rc = br_captures_find(compiled->email, input, &emails, true, &owned_error);
    for (size_t e = 0; !rc && e < emails.len; ++e) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            br_result result = {0}; cloze_outcome outcome = CLOZE_KEEP;
            br_slice key = br_captures_at(&keys, k);
            /* Emails are REQUIRED but HIDDEN. Do not add email parts, RawV2,
             * Redacted or detector-local dedup of identical NoV projections. */
            if (br_finding_key_bytes(&result, detector->type, key, "key")) {
                fail(&owned_error, "cannot create Cloze result"); outcome = CLOZE_ABORT;
            }
            if (outcome == CLOZE_KEEP && verify) outcome = verify_cloze(ctx, key, br_captures_at(&emails, e), &result, &owned_error);
            if (outcome == CLOZE_KEEP && br_results_push(out, &result)) {
                fail(&owned_error, "cannot append Cloze result"); outcome = CLOZE_ABORT;
            }
            br_result_clear(&result);
            if (outcome == CLOZE_ABORT) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&emails);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static cloze_patterns patterns;
static const char *const keywords[] = {"cloze"};
static const br_detector cloze = {
    .type = 711, .version = 0, .name = "Cloze", .custom_name = "",
    .description = "Cloze is a relationship management tool that helps users manage their connections and interactions. Cloze API keys can be used to access and manage user data and interactions.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_cloze,
};

int br_cloze_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Cloze detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{32})\\b", &patterns.key, error)) return -1;
    if (!patterns.email && br_regex_compile_prefixed(keywords, 1, br_email_pattern, &patterns.email, error)) return -1;
    *out = &cloze;
    return 0;
}
