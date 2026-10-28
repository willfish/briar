/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/eagleeyenetworks/eagleeyenetworks.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } eagleeye_patterns;

static int eagleeye_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor-error continue, never a false finding. */
static bool eagleeye_verify(const br_scan_ctx *ctx, br_slice key, br_slice email, br_result *result)
{
    static const char start[] = "{\"username\": \"";
    static const char middle[] = "\", \"password\": \"";
    static const char finish[] = "\"}";
    /* Other email characters are ASCII. The deliberately unescaped regex dot
     * consumes at most ONE Unicode scalar (four bytes): max email=42 bytes,
     * max key=15 bytes, max complete body=89 bytes plus the final NUL. */
    unsigned char body[90];
    _Static_assert(sizeof(start) - 1 + 42 + sizeof(middle) - 1 + 15 + sizeof(finish) == sizeof(body),
                   "EagleEyeNetworks body must fit 89 bytes plus NUL");
    size_t at = 0;
    memcpy(body + at, start, sizeof(start) - 1); at += sizeof(start) - 1;
    memcpy(body + at, email.data, email.len); at += email.len;
    memcpy(body + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(body + at, key.data, key.len); at += key.len;
    memcpy(body + at, finish, sizeof(finish));
    size_t body_len = at + sizeof(finish) - 1;
    /* Source fmt interpolates ORIGINAL bytes, including interior NUL, quotes,
     * backslashes and controls. Do not serialize/escape/strlen the email, even
     * when the result is invalid JSON. This bounded preparation cannot fail. */
    if (!ctx) return false; /* Finding AND complete payload precede the ctor skip. */
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://login.eagleeyenetworks.com/g/aaa/authenticate",
        .headers = headers, .nheaders = 1, .body = {body, body_len},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. No
     * verification-error setter, diagnostic classifier or successful-pair break. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Keep the full byte-slice body alive through BOTH send and release. Body/
     * read errors never affect verification. Source scan-deferred Close-only
     * timing, native POST redirects/private clients, regexp invalid-UTF-8 and
     * global engine/output parity remain partial; native guards stay intact. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int eagleeye_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return eagleeye_fail(error, "invalid EagleEyeNetworks scan");
    const eagleeye_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->email) return eagleeye_fail(error, "uninitialized EagleEyeNetworks scan");
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->email, input, &emails, false, &owned_error);
    /* Both TrimSpace calls are no-ops: captures start/end in ASCII alphanumerics.
     * Keep ALL occurrences, including keys that are 15-byte email fragments.
     * Email is required but HIDDEN: it never becomes RawV2 or a secret part. */
    for (size_t k = 0; !rc && k < keys.len; ++k) for (size_t e = 0; !rc && e < emails.len; ++e) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, k), email = br_captures_at(&emails, e);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = eagleeye_fail(&owned_error, "cannot create EagleEyeNetworks finding");
        if (!rc && verify) keep = eagleeye_verify(ctx, key, email, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = eagleeye_fail(&owned_error, "cannot append EagleEyeNetworks finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&emails);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static eagleeye_patterns eagleeye_compiled;
static const char *const eagleeye_keywords[] = {"eagleeyenetworks"};
static const br_detector eagleeye_detector = {
    .type = 639, .version = 0, .name = "EagleEyeNetworks", .custom_name = "",
    .description = "Eagle Eye Networks provides cloud-based video surveillance solutions. The credentials can be used to access and manage surveillance data.",
    .keywords = eagleeye_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &eagleeye_compiled, .scan = eagleeye_scan,
};

int br_eagleeyenetworks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return eagleeye_fail(error, "invalid EagleEyeNetworks detector output");
    *out = NULL;
    if (!eagleeye_compiled.key) {
        br_regex *key = NULL, *email = NULL;
        int rc = br_regex_compile_prefixed(eagleeye_keywords, 1, "\\b([a-zA-Z0-9]{15})\\b", &key, error);
        /* The source dot is a WILDCARD, not an escaped dot or RFC email grammar. */
        if (!rc) rc = br_regex_compile_prefixed(eagleeye_keywords, 1,
            "\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", &email, error);
        if (rc) { br_regex_free(key); br_regex_free(email); return -1; }
        eagleeye_compiled = (eagleeye_patterns){key, email};
    }
    *out = &eagleeye_detector;
    return 0;
}
