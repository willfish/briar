/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/{adzuna,aeroworkflow,agora,aha}. */
#include "third_batch.h"
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *part; } detector_patterns;
typedef int (*verifier)(const br_scan_ctx *, const char *, const char *, br_result *);

static int fail(char **error, const char *message)
{
    if (error) {
        size_t len = strlen(message) + 1;
        *error = malloc(len);
        if (*error) memcpy(*error, message, len);
    }
    return -1;
}

static int key_error(br_result *result, const char *cause)
{
    /* Each of these upstream scanners redacts the key, not the other part. */
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int unexpected_status(br_result *result, int status)
{
    char message[80];
    snprintf(message, sizeof(message), "unexpected HTTP response status %d", status);
    return key_error(result, message);
}

static int verify_aeroworkflow(const br_scan_ctx *ctx, const char *key,
                               const char *id, br_result *result)
{
    static const char prefix[] = "https://api.aeroworkflow.com/api/";
    static const char suffix[] = "/me";
    size_t id_len = strlen(id);
    if (id_len > SIZE_MAX - sizeof(prefix) - sizeof(suffix)) return -1;
    size_t len = sizeof(prefix) - 1 + id_len + sizeof(suffix);
    char *url = malloc(len);
    if (!url) return -1;
    snprintf(url, len, "%s%s%s", prefix, id, suffix);
    const br_header headers[] = {{"Accept", "application/json"}, {"apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 693,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    free(url);
    return rc;
}

static void agora_basic_auth(const char *key, const char *secret, char out[95])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char credentials[65];
    /* SetBasicAuth(secret, key): the secret is the username, not the password. */
    memcpy(credentials, secret, 32);
    credentials[32] = ':';
    memcpy(credentials + 33, key, 32);
    memcpy(out, "Basic ", 6);
    size_t at = 6;
    for (size_t i = 0; i < sizeof(credentials); i += 3) {
        size_t remaining = sizeof(credentials) - i;
        unsigned int word = (unsigned int)credentials[i] << 16;
        if (remaining > 1) word |= (unsigned int)credentials[i + 1] << 8;
        if (remaining > 2) word |= credentials[i + 2];
        out[at++] = alphabet[(word >> 18) & 63];
        out[at++] = alphabet[(word >> 12) & 63];
        out[at++] = remaining > 1 ? alphabet[(word >> 6) & 63] : '=';
        out[at++] = remaining > 2 ? alphabet[word & 63] : '=';
    }
    out[at] = '\0';
}

static int verify_agora(const br_scan_ctx *ctx, const char *key,
                         const char *secret, br_result *result)
{
    char auth[95];
    agora_basic_auth(key, secret, auth);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.agora.io/dev/v1/projects",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 197,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200:
        case 201: result->verified = true; break;
        case 401:
        case 403: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int verify_aha(const br_scan_ctx *ctx, const char *key,
                       const char *host, br_result *result)
{
    char url[128], auth[72];
    snprintf(url, sizeof(url), "https://%s/api/v1/me", host);
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.aha+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 802,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 404:
        case 403: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int emit_result(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const char *key, const char *part, const char *part_name,
                        verifier check, br_results *out, char **error)
{
    br_result result = {0};
    if (br_finding_pair(&result, detector->type, key, "key", part, part_name) != 0)
        goto memory_error;
    if (verify && check(ctx, key, part, &result) != 0) goto memory_error;
    if (br_results_push(out, &result) != 0) goto memory_error;
    return 0;
memory_error:
    br_result_clear(&result);
    return fail(error, "out of memory creating detector result");
}

static int valid_scan(const br_detector *detector, br_slice input,
                       br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid detector scan arguments");
    const detector_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->part)
        return fail(error, "uninitialized third-batch detector");
    return 0;
}

static int scan_ordered_pairs(const br_detector *detector, const br_scan_ctx *ctx,
                               bool verify, br_slice input, br_results *out, char **error,
                               const char *part_name, bool skip_equal, verifier check)
{
    if (valid_scan(detector, input, out, error) != 0) return -1;
    const detector_patterns *patterns = detector->state;
    br_captures keys = {0}, parts = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->part, input, &parts, false, error);
    /* All capture alphabets exclude whitespace: upstream TrimSpace is a no-op. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t p = 0; rc == 0 && p < parts.len; ++p) {
            if (skip_equal && !strcmp(keys.items[k], parts.items[p])) continue;
            rc = emit_result(detector, ctx, verify, keys.items[k], parts.items[p],
                             part_name, check, out, error);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&parts);
    return rc;
}

static int scan_aeroworkflow(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    return scan_ordered_pairs(detector, ctx, verify, input, out, error, "id", false, verify_aeroworkflow);
}

static int scan_agora(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return scan_ordered_pairs(detector, ctx, verify, input, out, error, "secret", true, verify_agora);
}

static int scan_aha(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (valid_scan(detector, input, out, error) != 0) return -1;
    const detector_patterns *patterns = detector->state;
    br_captures keys = {0}, hosts = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->part, input, &hosts, true, error);
    if (rc == 0 && hosts.len == 0)
        rc = br_captures_push(&hosts, (br_slice){(const unsigned char *)"aha.io", 6}, false, error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k)
        for (size_t h = 0; rc == 0 && h < hosts.len; ++h)
            rc = emit_result(detector, ctx, verify, keys.items[k], hosts.items[h],
                             "url", verify_aha, out, error);
    br_captures_clear(&keys);
    br_captures_clear(&hosts);
    return rc;
}

static detector_patterns aeroworkflow_patterns, agora_patterns, aha_patterns;
static const char *const aeroworkflow_keywords[] = {"aeroworkflow"};
static const char *const agora_keywords[] = {"agora"};
static const char *const aha_keywords[] = {"aha.io"};
static const char *const agora_key_prefix[] = {"agora", "key", "token"};
static const char *const agora_secret_prefix[] = {"agora", "secret"};
static const char *const aha_key_prefix[] = {"aha"};

static const br_detector aeroworkflow = {
    .type = 693, .version = 0, .name = "Aeroworkflow", .custom_name = "",
    .description = "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys and Account IDs can be used to access and manage workflows.",
    .keywords = aeroworkflow_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &aeroworkflow_patterns, .scan = scan_aeroworkflow,
};
static const br_detector agora = {
    .type = 197, .version = 0, .name = "Agora", .custom_name = "",
    .description = "Agora is a real-time engagement platform providing APIs for voice, video, and messaging. Agora API keys can be used to access and manage these services.",
    .keywords = agora_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &agora_patterns, .scan = scan_agora,
};
static const br_detector aha = {
    .type = 802, .version = 0, .name = "Aha", .custom_name = "",
    .description = "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows.",
    .keywords = aha_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &aha_patterns, .scan = scan_aha,
};
static const br_detector *implemented[] = {NULL, &aeroworkflow, &agora, &aha};

static int compile_prefixed(const char *const *keywords, size_t count, const char *capture,
                             br_regex **out, char **error)
{
    if (*out) return 0;
    return br_regex_compile_prefixed(keywords, count, capture, out, error);
}

int br_third_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid third-batch outputs");
    if (br_adzuna_init(&implemented[0], error) != 0 ||
        compile_prefixed(aeroworkflow_keywords, 1, "\\b([a-zA-Z0-9^!?#:*;]{20})", &aeroworkflow_patterns.key, error) != 0 ||
        compile_prefixed(aeroworkflow_keywords, 1, "\\b([0-9]{1,})\\b", &aeroworkflow_patterns.part, error) != 0 ||
        compile_prefixed(agora_key_prefix, 3, "\\b([a-z0-9]{32})\\b", &agora_patterns.key, error) != 0 ||
        compile_prefixed(agora_secret_prefix, 2, "\\b([a-z0-9]{32})\\b", &agora_patterns.part, error) != 0 ||
        compile_prefixed(aha_key_prefix, 1, "\\b([0-9a-f]{64})\\b", &aha_patterns.key, error) != 0)
        return -1;
    if (!aha_patterns.part &&
        br_regex_compile("\\b([A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])\\.aha\\.io)",
                         &aha_patterns.part, error) != 0) return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_third_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == 431 || detector->type == 693 || detector->type == 197 || detector->type == 802;
}
