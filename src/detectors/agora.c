/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/agora/agora.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } agora_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_agora(const br_scan_ctx *ctx, const char *key,
                         const char *secret, br_result *result)
{
    char *auth = NULL;
    /* SetBasicAuth(secret, key): the secret is the username, not the password. */
    if (br_http_basic_auth((br_slice){(const unsigned char *)secret, strlen(secret)},
                           (br_slice){(const unsigned char *)key, strlen(key)}, &auth, NULL) != 0)
        return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.agora.io/dev/v1/projects",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 197,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream only inspects status, ignoring the body and body-read errors. */
        switch (response.status) {
        case 200:
        case 201: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies only the key to SetVerificationError, not the secret. */
    br_slice redacted = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &redacted, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_agora(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Agora scan arguments");
    const agora_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->secret)
        return fail(error, "uninitialized Agora detector");

    br_captures keys = {0}, secrets = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(compiled->secret, input, &secrets, false, error);
    /* Both alphabets exclude whitespace, so TrimSpace is a no-op. Preserve
     * occurrences and key-outer/secret-inner order, skipping only equal values. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            if (!strcmp(keys.items[k], secrets.items[s])) continue;
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                secrets.items[s], "secret") != 0 ||
                (verify && verify_agora(ctx, keys.items[k], secrets.items[s], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Agora result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    return rc;
}

static agora_patterns patterns;
/* The engine prefilter is narrower than the two extraction-prefix OR lists. */
static const char *const keywords[] = {"agora"};
static const char *const key_prefixes[] = {"agora", "key", "token"};
static const char *const secret_prefixes[] = {"agora", "secret"};
static const br_detector agora = {
    .type = 197, .version = 0, .name = "Agora", .custom_name = "",
    .description = "Agora is a real-time engagement platform providing APIs for voice, video, "
                   "and messaging. Agora API keys can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_agora,
};

int br_agora_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Agora detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(key_prefixes, 3, "\\b([a-z0-9]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.secret &&
        br_regex_compile_prefixed(secret_prefixes, 2, "\\b([a-z0-9]{32})\\b", &patterns.secret, error) != 0)
        return -1;
    *out = &agora;
    return 0;
}
