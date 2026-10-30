/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/plaidkey/plaidkey.go. */
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int plaidkey_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *secret, *id, *token; } plaidkey_patterns;

static int plaidkey_part(br_json *object, const char *name, br_slice value, char **error)
{
    if ((!value.data && value.len) || value.len > INT_MAX)
        return plaidkey_fail(error, "cannot create PlaidKey result");
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part) return plaidkey_fail(error, "cannot create PlaidKey result");
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return plaidkey_fail(error, "cannot create PlaidKey result");
    }
    return 0;
}

/* The shared helper owns two parts. This finding is secret, id, and token. */
static int plaidkey_finding(br_result *result, br_slice secret, br_slice id, br_slice token, char **error)
{
    if (br_finding_key_bytes(result, 79, secret, "secret") != 0)
        return plaidkey_fail(error, "cannot create PlaidKey result");
    if (id.len > SIZE_MAX - 2 || token.len > SIZE_MAX - 2 - id.len ||
        secret.len > SIZE_MAX - 2 - id.len - token.len) {
        br_result_clear(result);
        return plaidkey_fail(error, "cannot create PlaidKey result");
    }
    size_t len = secret.len + 1 + id.len + 1 + token.len;
    result->raw_v2.data = malloc(len ? len : 1);
    if (!result->raw_v2.data) {
        br_result_clear(result);
        return plaidkey_fail(error, "cannot create PlaidKey result");
    }
    result->raw_v2.len = len;
    unsigned char *at = result->raw_v2.data;
    memcpy(at, secret.data, secret.len); at += secret.len; *at++ = ':';
    memcpy(at, id.data, id.len); at += id.len; *at++ = ':';
    memcpy(at, token.data, token.len);
    if (plaidkey_part(result->secret_parts, "id", id, error) != 0 ||
        plaidkey_part(result->secret_parts, "token", token, error) != 0) {
        br_result_clear(result);
        return -1;
    }
    return 0;
}

static int plaidkey_extra(br_result *result, const char *environment, char **error)
{
    char url[48];
    int n = snprintf(url, sizeof(url), "https://%s.plaid.com", environment);
    if (n < 0 || (size_t)n >= sizeof(url)) return plaidkey_fail(error, "cannot create PlaidKey extra data");
    result->extra_data = json_object_new_object();
    br_json *value = json_object_new_string(url);
    if (!result->extra_data || !value) {
        json_object_put(value);
        return plaidkey_fail(error, "cannot create PlaidKey extra data");
    }
    if (json_object_object_add(result->extra_data, "environment", value) != 0) {
        json_object_put(value);
        return plaidkey_fail(error, "cannot create PlaidKey extra data");
    }
    return 0;
}

static int plaidkey_body(br_slice id, br_slice secret, br_slice token, unsigned char **out, size_t *len, char **error)
{
    static const char prefix[] = "{\"client_id\":\"", mid[] = "\",\"secret\":\"", tail[] = "\",\"access_token\":\"";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(mid) - 1 + sizeof(tail) - 1 + 2;
    if (id.len > SIZE_MAX - fixed || secret.len > SIZE_MAX - fixed - id.len ||
        token.len > SIZE_MAX - fixed - id.len - secret.len)
        return plaidkey_fail(error, "cannot construct PlaidKey request");
    *len = fixed + id.len + secret.len + token.len;
    *out = malloc(*len + 1);
    if (!*out) return plaidkey_fail(error, "cannot construct PlaidKey request");
    unsigned char *at = *out;
    memcpy(at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(at, id.data, id.len); at += id.len;
    memcpy(at, mid, sizeof(mid) - 1); at += sizeof(mid) - 1;
    memcpy(at, secret.data, secret.len); at += secret.len;
    memcpy(at, tail, sizeof(tail) - 1); at += sizeof(tail) - 1;
    memcpy(at, token.data, token.len); at += token.len;
    *at++ = '"'; *at = '}';
    (*out)[*len] = 0;
    return 0;
}

static int plaidkey_cause(const char *text, char **cause, char **error)
{
    *cause = strdup(text);
    return *cause ? 0 : plaidkey_fail(error, "cannot retain PlaidKey verification cause");
}

static int plaidkey_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret, br_slice token,
                            const char *environment, bool *verified, char **cause, char **error)
{
    unsigned char *body = NULL; size_t body_len = 0;
    *verified = false; *cause = NULL;
    /* Concatenated body precedes the constructor. No JSON escaping. */
    if (plaidkey_body(id, secret, token, &body, &body_len, error) != 0) return -1;
    if (!ctx) {
        free(body);
        return plaidkey_cause("net/http: nil Context", cause, error);
    }
    char url[64];
    int n = snprintf(url, sizeof(url), "https://%s.plaid.com/item/get", environment);
    if (n < 0 || (size_t)n >= sizeof(url)) { free(body); return plaidkey_fail(error, "cannot construct PlaidKey request"); }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {body, body_len}, .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 79,
    };
    br_http_response response = {0}; char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (send_rc != 0) {
        *cause = send_error; send_error = NULL;
    } else if (response.status == 200) {
        *verified = true;
    } else if (response.status != 400) {
        char text[64];
        n = snprintf(text, sizeof(text), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(text)) rc = plaidkey_fail(error, "cannot format PlaidKey status cause");
        else rc = plaidkey_cause(text, cause, error);
    }
    /* One close per attempted send, before the caller setter and publication.
     * Body, URL, and header storage remain valid through this release. */
    br_http_release(ctx, &response);
    free(send_error); free(body);
    return rc;
}

static bool plaidkey_keep(br_slice value)
{
    return br_ascii_shannon_entropy(value) >= 3;
}

static int plaidkey_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return plaidkey_fail(error, "invalid or uninitialized PlaidKey scan");
    const plaidkey_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures secrets = {0}, ids = {0}, tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
        br_slice secret = br_captures_at(&secrets, s);
        if (!plaidkey_keep(secret)) continue;
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            if (!plaidkey_keep(id)) continue;
            for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
                br_slice token = br_captures_at(&tokens, t);
                if (!plaidkey_keep(token)) continue;
                br_result result = {0};
                if (plaidkey_finding(&result, secret, id, token, &owned_error) != 0) rc = -1;
                if (rc == 0 && verify) {
                    static const char production[] = "production";
                    const char *environment = br_slice_find(token, (br_slice){(const unsigned char *)production, sizeof(production) - 1}, 0) != SIZE_MAX
                        ? production : "sandbox";
                    bool verified = false; char *cause = NULL;
                    br_slice redact[2] = {id, secret};
                    if (plaidkey_verify(ctx, id, secret, token, environment, &verified, &cause, &owned_error) != 0) rc = -1;
                    if (rc == 0) result.verified = verified;
                    if (rc == 0 && plaidkey_extra(&result, environment, &owned_error) != 0) rc = -1;
                    /* Mandatory, including a nil cause. Redact id and secret, never token. */
                    if (rc == 0 && br_result_set_verification_error(&result, cause, redact, 2) != 0)
                        rc = plaidkey_fail(&owned_error, "cannot set PlaidKey verification error");
                    free(cause);
                }
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = plaidkey_fail(&owned_error, "cannot append PlaidKey result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens); br_captures_clear(&ids); br_captures_clear(&secrets);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const plaidkey_keywords[] = {"plaid"};
static plaidkey_patterns plaidkey_compiled;
static br_detector plaidkey_detector = {
    .type = 79, .version = 0, .name = "PlaidKey", .custom_name = "",
    .description = "Plaid is a financial services company that provides a way to connect applications to users' bank accounts. Plaid API keys can be used to access and manage financial data.",
    .keywords = plaidkey_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = plaidkey_scan,
};

int br_plaidkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return plaidkey_fail(error, "invalid PlaidKey detector output");
    *out = NULL;
    if (!plaidkey_detector.state) {
        plaidkey_patterns patterns = {0};
        if (br_regex_compile_prefixed(plaidkey_keywords, 1, "\\b([a-f0-9]{30})\\b", &patterns.secret, error) != 0) return -1;
        if (br_regex_compile_prefixed(plaidkey_keywords, 1, "\\b([a-f0-9]{24})\\b", &patterns.id, error) != 0) {
            br_regex_free(patterns.secret); return -1;
        }
        if (br_regex_compile_prefixed(plaidkey_keywords, 1,
            "\\b(access-(sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\b",
            &patterns.token, error) != 0) {
            br_regex_free(patterns.id); br_regex_free(patterns.secret); return -1;
        }
        plaidkey_compiled = patterns; plaidkey_detector.state = &plaidkey_compiled;
    }
    *out = &plaidkey_detector;
    return 0;
}
