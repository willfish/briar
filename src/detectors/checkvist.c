/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/checkvist/checkvist.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } checkvist_patterns;
typedef enum { CV_ABORT = -1, CV_KEEP = 0, CV_SKIP = 1 } checkvist_outcome;

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

/* A provider-local, byte-aware QueryEscape for this form's email value.
 * Returns positive 1 for ANY resource/size failure, never a candidate skip. */
static int form_body(br_slice key, br_slice email, br_bytes *out)
{
    static const char remote[] = "remote_key=", username[] = "&username=";
    static const char hex[] = "0123456789ABCDEF";
    *out = (br_bytes){0};
    size_t encoded = 0;
    for (size_t i = 0; i < email.len; ++i) {
        size_t width = unreserved(email.data[i]) || email.data[i] == ' ' ? 1 : 3;
        if (encoded > SIZE_MAX - width) return 1;
        encoded += width;
    }
    /* Key is exactly 14 captured ASCII alphanumerics, already unreserved. */
    size_t prefix = sizeof(remote) - 1 + key.len + sizeof(username) - 1;
    if (encoded > SIZE_MAX - prefix) return 1;
    unsigned char *body = malloc(prefix + encoded);
    if (!body) return 1;
    size_t at = 0;
    memcpy(body + at, remote, sizeof(remote) - 1); at += sizeof(remote) - 1;
    memcpy(body + at, key.data, key.len); at += key.len;
    memcpy(body + at, username, sizeof(username) - 1); at += sizeof(username) - 1;
    for (size_t i = 0; i < email.len; ++i) {
        unsigned char c = email.data[i];
        if (unreserved(c)) body[at++] = c;
        else if (c == ' ') body[at++] = '+';
        else { body[at++] = '%'; body[at++] = hex[c >> 4]; body[at++] = hex[c & 15]; }
    }
    *out = (br_bytes){body, at}; /* Length-bearing payload, no needless C-string copy. */
    return 0;
}

static checkvist_outcome verify_checkvist(const br_scan_ctx *ctx, br_slice key, br_slice email,
                                           br_result *result, char **error)
{
    br_bytes body = {0};
    /* Source encodes the complete form BEFORE NewRequestWithContext. A form
     * helper failure (including +1) is ABORT, not SKIP or a suppressed Do error. */
    if (form_body(key, email, &body)) { fail(error, "cannot construct Checkvist form body"); return CV_ABORT; }
    if (!ctx) { free(body.data); return CV_SKIP; }
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "GET", .url = "https://checkvist.com/auth/login.json?version=2",
        .headers = headers, .nheaders = 1, .body = {body.data, body.len},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* ALL Do errors keep an unverified finding. ABI1 also mixes adapter setup
     * and allocation errors here. Native curl rejects nonempty GET bodies
     * before I/O; its diagnostic is suppressed, not bypassed by POST/query. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Source scan-defers Close ONLY; eager ABI1
     * buffering/per-request release does not establish native lifecycle parity. */
    br_http_release(ctx, &response);
    free(transport_error); free(body.data);
    return CV_KEEP;
}

static int scan_checkvist(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Checkvist scan");
    const checkvist_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->email) return fail(error, "uninitialized Checkvist patterns");
    br_captures keys = {0}, emails = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    /* Standard capture ONE, not Alegra's full-match/last-space projection.
     * This grammar's outer bytes are never whitespace, so TrimSpace is a no-op.
     * Bytewise uniqueness preserves original email case and quoted controls. */
    if (!rc) rc = br_captures_find(compiled->email, input, &emails, true, &owned_error);
    for (size_t e = 0; !rc && e < emails.len; ++e) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            br_result result = {0}; checkvist_outcome outcome = CV_KEEP;
            br_slice email = br_captures_at(&emails, e), key = br_captures_at(&keys, k);
            /* Keep EVERY email-major/key-occurrence pair, including keys that
             * came from 14-byte email local parts. No consumption/success break. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", email, "email", (br_slice){0})) {
                fail(&owned_error, "cannot create Checkvist result"); outcome = CV_ABORT;
            }
            if (outcome == CV_KEEP && verify) outcome = verify_checkvist(ctx, key, email, &result, &owned_error);
            if (outcome == CV_KEEP && br_results_push(out, &result)) {
                fail(&owned_error, "cannot append Checkvist result"); outcome = CV_ABORT;
            }
            br_result_clear(&result);
            if (outcome == CV_ABORT) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&emails);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static checkvist_patterns patterns;
static const char *const keywords[] = {"checkvist"};
static const br_detector checkvist = {
    .type = 709, .version = 0, .name = "Checkvist", .custom_name = "",
    .description = "Checkvist is an online task management tool. The credentials found can be used to access and manage tasks and data within Checkvist.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_checkvist,
};

int br_checkvist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Checkvist detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-zA-Z]{14})\\b", &patterns.key, error)) return -1;
    if (!patterns.email && br_regex_compile_prefixed(keywords, 1, br_email_pattern, &patterns.email, error)) return -1;
    *out = &checkvist;
    return 0;
}
