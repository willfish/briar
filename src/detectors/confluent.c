/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/confluent/confluent.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } confluent_patterns;
typedef enum { CONFLUENT_ABORT = -1, CONFLUENT_KEEP = 0, CONFLUENT_SKIP = 1 } confluent_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static confluent_outcome verify_confluent(const br_scan_ctx *ctx, br_slice key,
                                          br_slice secret, br_result *result, char **error)
{
    /* Source prepares KEY + ':' + SECRET and standard Base64 BEFORE the
     * context-bound constructor. Fixed captures need no heap auth copies. */
    unsigned char credentials[81];
    memcpy(credentials, key.data, 16);
    credentials[16] = ':';
    memcpy(credentials + 17, secret.data, 64);
    char authorization[115];
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 108) {
        fail(error, "Confluent native Base64 encoding failed");
        return CONFLUENT_ABORT;
    }
    authorization[114] = '\0'; /* 81 bytes encode to 108 characters, without '='. */
    static const char prefix[] = "https://api.confluent.cloud/iam/v2/api-keys/";
    char url[sizeof(prefix) - 1 + 16 + 1];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 16);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return CONFLUENT_SKIP;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines shared setup/allocation with Do. Source suppresses every
     * Do error; suppress this entire domain, never classifying diagnostic text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Both stack buffers live through release. Source scan-defers Close ONLY,
     * ignoring bodies/read errors. Eager buffering/per-request release, full
     * native SANE-client behavior and global engine/output parity stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return CONFLUENT_KEEP;
}

static int scan_confluent(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Confluent scan");
    const confluent_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->secret) return fail(error, "uninitialized Confluent patterns");
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    /* Independent FindAll matches, in key-major/secret-minor occurrence order.
     * TrimSpace is a no-op; no uniqueness, consumption, distance or entropy filter. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice key = br_captures_at(&keys, k), secret = br_captures_at(&secrets, s);
            br_result result = {0};
            confluent_outcome outcome = CONFLUENT_KEEP;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret", (br_slice){0})) {
                fail(&owned_error, "cannot create Confluent result");
                outcome = CONFLUENT_ABORT;
            }
            if (outcome == CONFLUENT_KEEP && verify)
                outcome = verify_confluent(ctx, key, secret, &result, &owned_error);
            if (outcome == CONFLUENT_KEEP && br_results_push(out, &result)) {
                fail(&owned_error, "cannot append Confluent result");
                outcome = CONFLUENT_ABORT;
            }
            br_result_clear(&result);
            if (outcome == CONFLUENT_ABORT) rc = -1;
        }
    }
    if (rc)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"confluent"};
static confluent_patterns compiled;
static br_detector confluent = {
    .type = 60, .version = 0, .name = "Confluent", .custom_name = "",
    .description = "Confluent provides a streaming platform based on Apache Kafka to help companies harness their data in real-time. Confluent API keys can be used to access and manage Kafka clusters.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_confluent,
};

int br_confluent_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Confluent detector output");
    *out = NULL;
    if (!confluent.state) {
        confluent_patterns patterns = {0};
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9]{16})\\b", &patterns.key, error)) return -1;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9\\+\\/]{64})\\b", &patterns.secret, error)) {
            br_regex_free(patterns.key);
            return -1;
        }
        compiled = patterns;
        confluent.state = &compiled;
    }
    *out = &confluent;
    return 0;
}
