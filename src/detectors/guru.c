/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/guru/guru.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *username, *key; } guru_patterns;
typedef enum { GURU_ABORT = -1, GURU_KEEP = 0, GURU_SKIP = 1 } guru_outcome;

static int guru_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static guru_outcome guru_verify(const br_scan_ctx *ctx, br_slice username, br_slice key,
                                br_result *result, char **error)
{
    /* At most 20+1+12+4+5 username bytes, ':' and 36 key bytes. The dot
     * matches a rune, including NUL, so strlen must never size this payload. */
    unsigned char payload[79], encoded[109];
    size_t len = username.len + 1 + key.len;
    memcpy(payload, username.data, username.len);
    payload[username.len] = ':';
    memcpy(payload + username.len + 1, key.data, key.len);
    size_t encoded_len = 4 * ((len + 2) / 3);
    if (EVP_EncodeBlock(encoded, payload, (int)len) != (int)encoded_len) {
        guru_fail(error, "Guru native Base64 encoding failed");
        return GURU_ABORT;
    }
    /* EncodeToString precedes NewRequestWithContext; Basic assembly follows it. */
    if (!ctx) return GURU_SKIP;
    char authorization[115];
    if (encoded_len > sizeof(authorization) - sizeof("Basic ")) {
        guru_fail(error, "cannot construct Guru Authorization");
        return GURU_ABORT;
    }
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, encoded, encoded_len);
    authorization[6 + encoded_len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.getguru.com/api/v1/teams/teamId/stats",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the entire shared setup/Do domain, not diagnostic categories.
     * Source never reads the body, including body-read errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider-original auth/captures survive release. Ordinary ABI1 prepared
     * headers/UA do not. Eager release differs from source's deferred Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return GURU_KEEP;
}

static int guru_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return guru_fail(error, "invalid or uninitialized Guru scan");
    const guru_patterns *patterns = detector->state;
    if (!patterns->username || !patterns->key)
        return guru_fail(error, "uninitialized Guru patterns");
    size_t original_len = out->len;
    br_captures usernames = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->username, input, &usernames, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Independent occurrence lists, username-major Cartesian product, no unique
     * filtering. TrimSpace is a no-op on these alphanumeric capture edges. */
    for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
        for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
            br_slice username = br_captures_at(&usernames, u), key = br_captures_at(&keys, k);
            br_result result = {0};
            guru_outcome outcome = GURU_KEEP;
            if (username.len < 9 || username.len > 42 || key.len != 36) {
                guru_fail(&owned_error, "invalid Guru capture"); outcome = GURU_ABORT;
            } else if (br_finding_key_bytes(&result, detector->type, username, "key") != 0) {
                guru_fail(&owned_error, "cannot create Guru result"); outcome = GURU_ABORT;
            } else if (verify) outcome = guru_verify(ctx, username, key, &result, &owned_error);
            /* The API key is required but hidden: Raw and SecretParts.key are
             * the original username bytes, not a pair or the API key. */
            if (outcome == GURU_KEEP && br_results_push(out, &result) != 0) {
                guru_fail(&owned_error, "cannot append Guru result"); outcome = GURU_ABORT;
            }
            br_result_clear(&result);
            if (outcome == GURU_ABORT) rc = -1;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&usernames);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static guru_patterns guru_compiled;
static const char *const guru_keywords[] = {"guru"};
static const br_detector guru_detector = {
    .type = 570, .version = 0, .name = "Guru", .custom_name = "",
    .description = "Guru is a knowledge management solution. Guru credentials can be used to access and manage knowledge within an organization.",
    .keywords = guru_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &guru_compiled, .scan = guru_scan,
};

int br_guru_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return guru_fail(error, "invalid Guru detector output");
    *out = NULL;
    if (!guru_compiled.username && br_regex_compile_prefixed(guru_keywords, 1,
        "\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b",
        &guru_compiled.username, error) != 0) return -1;
    if (!guru_compiled.key && br_regex_compile_prefixed(guru_keywords, 1,
        "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
        &guru_compiled.key, error) != 0) return -1;
    *out = &guru_detector;
    return 0;
}
