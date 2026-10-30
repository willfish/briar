/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/salesforcerefreshtoken/salesforcerefreshtoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include <json-c/json.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const salesforce_keywords[] = {"salesforce", "5AEP861", "3MVG9"};
static const char salesforce_url[] = "https://login.salesforce.com/services/oauth2/introspect";

typedef struct { br_regex *token; br_regex *key; br_regex *secret; } salesforce_patterns;

static int salesforce_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool salesforce_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static int salesforce_escape(br_slice value, char **out, size_t *out_len)
{
    if (value.len > (SIZE_MAX - 1) / 3) return -1;
    char *encoded = malloc(value.len * 3 + 1);
    if (!encoded) return -1;
    static const char hex[] = "0123456789ABCDEF";
    size_t at = 0;
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        if (salesforce_unreserved(c)) encoded[at++] = (char)c;
        else if (c == ' ') encoded[at++] = '+';
        else {
            encoded[at++] = '%';
            encoded[at++] = hex[c >> 4];
            encoded[at++] = hex[c & 15];
        }
    }
    encoded[at] = '\0';
    *out = encoded;
    *out_len = at;
    return 0;
}

static int salesforce_form(br_slice token, br_slice key, br_slice secret, char **out, size_t *out_len)
{
    char *token_e = NULL, *key_e = NULL, *secret_e = NULL;
    size_t token_n = 0, key_n = 0, secret_n = 0;
    *out = NULL;
    if (salesforce_escape(key, &key_e, &key_n) || salesforce_escape(secret, &secret_e, &secret_n) ||
        salesforce_escape(token, &token_e, &token_n)) {
        free(key_e); free(secret_e); free(token_e);
        return -1;
    }
    /* url.Values.Encode sorts client_id, client_secret, token. */
    static const char id[] = "client_id=", secret_name[] = "&client_secret=", token_name[] = "&token=";
    size_t n = sizeof(id) - 1 + key_n + sizeof(secret_name) - 1 + secret_n + sizeof(token_name) - 1 + token_n;
    char *body = malloc(n + 1);
    if (!body) { free(key_e); free(secret_e); free(token_e); return -1; }
    size_t at = 0;
    memcpy(body + at, id, sizeof(id) - 1); at += sizeof(id) - 1;
    memcpy(body + at, key_e, key_n); at += key_n;
    memcpy(body + at, secret_name, sizeof(secret_name) - 1); at += sizeof(secret_name) - 1;
    memcpy(body + at, secret_e, secret_n); at += secret_n;
    memcpy(body + at, token_name, sizeof(token_name) - 1); at += sizeof(token_name) - 1;
    memcpy(body + at, token_e, token_n); at += token_n;
    body[at] = '\0';
    free(key_e); free(secret_e); free(token_e);
    *out = body;
    *out_len = at;
    return 0;
}

typedef struct { bool active; bool ordinary; char *cause; } salesforce_active_fields;

static int salesforce_note(salesforce_active_fields *fields, char *next)
{
    if (fields->ordinary) { free(next); return 0; }
    fields->ordinary = true;
    fields->cause = next;
    return 0;
}

static int salesforce_active_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    salesforce_active_fields *fields = user;
    if (!br_json_field_name(name, "active")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_boolean)) {
        char *typed = NULL;
        if (br_json_type_cause(value, "introspectAPIResponse.active", "bool", &typed) != 0) {
            free(typed);
            return -1;
        }
        return salesforce_note(fields, typed);
    }
    fields->active = json_object_get_boolean(value);
    return 0;
}

static int salesforce_active(br_slice body, bool *active, char **cause)
{
    *active = false;
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc < 0 || rc > 1) { json_object_put(root); free(*cause); *cause = NULL; return -1; }
    if (rc == 1) { json_object_put(root); return 1; }
    if (json_object_is_type(root, json_type_null)) { json_object_put(root); return 0; }
    if (!json_object_is_type(root, json_type_object)) {
        char *typed = NULL;
        int typed_rc = br_json_type_cause(root, NULL, "salesforcerefreshtoken.introspectAPIResponse", &typed);
        json_object_put(root);
        if (typed_rc != 0) { free(typed); return -1; }
        *cause = typed;
        return 1;
    }
    json_object_put(root);
    salesforce_active_fields parsed = {0};
    rc = br_json_each_member(body, salesforce_active_member, &parsed);
    if (rc != 0) { free(parsed.cause); return -1; }
    if (parsed.ordinary) { *cause = parsed.cause; return 1; }
    *active = parsed.active;
    return 0;
}

static int salesforce_wrap(char **out, const char *prefix, const char *detail, const char *suffix)
{
    size_t n = strlen(prefix), m = detail ? strlen(detail) : 0, s = suffix ? strlen(suffix) : 0;
    if (m > SIZE_MAX - n - s - 1) return -1;
    char *message = malloc(n + m + s + 1);
    if (!message) return -1;
    memcpy(message, prefix, n);
    if (m) memcpy(message + n, detail, m);
    if (s) memcpy(message + n + m, suffix, s);
    message[n + m + s] = '\0';
    *out = message;
    return 0;
}

static int salesforce_verify(const br_scan_ctx *ctx, br_slice token, br_slice key, br_slice secret,
                             br_result *result, char **error)
{
    char *body = NULL;
    size_t body_len = 0;
    if (salesforce_form(token, key, secret, &body, &body_len) != 0)
        return salesforce_fail(error, "cannot encode SalesforceRefreshToken form");
    char *cause = NULL;
    bool send_failed = false;
    int rc = 0;
    if (!ctx) {
        rc = salesforce_wrap(&cause, "failed to create request: ", "net/http: nil Context", NULL);
    } else {
        const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
        const br_http_request request = {
            .method = "POST", .url = salesforce_url, .headers = headers, .nheaders = 1,
            .body = {(const unsigned char *)body, body_len},
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        int send_rc = br_http_send(ctx, &request, &response, &transport_error);
        if (send_rc != 0) {
            send_failed = true;
            if (transport_error)
                rc = salesforce_wrap(&cause, "failed to perform request: ", transport_error, NULL);
        }
        else if (response.status == 200) {
            if (response.body_error)
                rc = salesforce_wrap(&cause, "failed to read error response body: ", response.body_error, NULL);
            else {
                bool active = false;
                char *decode = NULL;
                int decoded = salesforce_active(response.body, &active, &decode);
                if (decoded < 0) rc = -1;
                else if (decoded > 0 && decode) {
                    char *tail = NULL;
                    if (salesforce_wrap(&tail, " (body: ", NULL, NULL) ||
                        response.body.len > SIZE_MAX - strlen(decode) - strlen("failed to unmarshal error response: ") - 8) {
                        rc = -1;
                    } else {
                        size_t prefix_n = strlen("failed to unmarshal error response: ");
                        size_t mid_n = strlen(decode), body_n = response.body.len;
                        char *message = malloc(prefix_n + mid_n + 8 + body_n + 1);
                        if (!message) rc = -1;
                        else {
                            memcpy(message, "failed to unmarshal error response: ", prefix_n);
                            memcpy(message + prefix_n, decode, mid_n);
                            memcpy(message + prefix_n + mid_n, " (body: ", 8);
                            if (body_n) memcpy(message + prefix_n + mid_n + 8, response.body.data, body_n);
                            message[prefix_n + mid_n + 8 + body_n] = '\0';
                            cause = message;
                        }
                    }
                    free(tail);
                    free(decode);
                } else if (decoded == 0) result->verified = active;
                else free(decode);
            }
        } else if (response.status == 401)
            cause = strdup("unauthorized: invalid client credentials");
        else if (response.status != 400) {
            char status_error[64];
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = salesforce_fail(error, "cannot format SalesforceRefreshToken status");
            else cause = strdup(status_error);
        }
        free(transport_error);
        br_http_release(ctx, &response);
    }
    if (!rc && (send_failed || cause) && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = -1;
    free(cause);
    free(body);
    return rc;
}

static int salesforce_result(br_result *result, int32_t type, br_slice token, br_slice key, br_slice secret)
{
    if (br_finding_key_bytes(result, type, token, "refresh_token") != 0) return -1;
    if (token.len > SIZE_MAX - 2 || key.len > SIZE_MAX - token.len - 2 ||
        secret.len > SIZE_MAX - token.len - key.len - 2) return -1;
    result->raw_v2.len = token.len + 1 + key.len + 1 + secret.len;
    result->raw_v2.data = malloc(result->raw_v2.len ? result->raw_v2.len : 1);
    br_json *key_part = json_object_new_string_len((const char *)key.data, (int)key.len);
    br_json *secret_part = json_object_new_string_len((const char *)secret.data, (int)secret.len);
    if (!result->raw_v2.data || !key_part || !secret_part || key.len > INT_MAX || secret.len > INT_MAX ||
        json_object_object_add(result->secret_parts, "consumer_key", key_part) != 0 ||
        json_object_object_add(result->secret_parts, "consumer_secret", secret_part) != 0) {
        json_object_put(key_part);
        json_object_put(secret_part);
        return -1;
    }
    size_t at = 0;
    if (token.len) memcpy(result->raw_v2.data + at, token.data, token.len);
    at += token.len;
    result->raw_v2.data[at++] = ':';
    if (key.len) memcpy(result->raw_v2.data + at, key.data, key.len);
    at += key.len;
    result->raw_v2.data[at++] = ':';
    if (secret.len) memcpy(result->raw_v2.data + at, secret.data, secret.len);
    return 0;
}

static int salesforce_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const salesforce_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->token || !patterns->key || !patterns->secret ||
        !out || (!input.data && input.len))
        return salesforce_fail(error, "invalid or uninitialized SalesforceRefreshToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0}, keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    for (size_t t = 0; !rc && t < tokens.len; ++t) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            for (size_t s = 0; !rc && s < secrets.len; ++s) {
                br_result result = {0};
                br_slice token = br_captures_at(&tokens, t);
                br_slice key = br_captures_at(&keys, k);
                br_slice secret = br_captures_at(&secrets, s);
                if (token.len < 87 || key.len < 85 || key.len > 256 || (secret.len != 64 && secret.len != 19))
                    rc = salesforce_fail(&owned_error, "invalid SalesforceRefreshToken capture");
                else if (salesforce_result(&result, detector->type, token, key, secret) != 0)
                    rc = salesforce_fail(&owned_error, "cannot create SalesforceRefreshToken result");
                else if (verify && salesforce_verify(ctx, token, key, secret, &result, &owned_error) != 0)
                    rc = -1;
                if (!rc && br_results_push(out, &result) != 0)
                    rc = salesforce_fail(&owned_error, "cannot append SalesforceRefreshToken result");
                br_result_clear(&result);
            }
        }
    }
    if (rc)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static br_detector salesforce_detector = {
    .type = 1031, .version = 0, .name = "SalesforceRefreshToken", .custom_name = "",
    .description = "Salesforce is a customer relationship management (CRM) platform that provides a suite of applications and APIs. OAuth 2.0 refresh tokens are long-lived credentials that allow applications to obtain new access tokens without requiring user interaction. They enable continuous access to an organization's data and must be handled securely.",
    .keywords = salesforce_keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = salesforce_scan,
};

int br_salesforcerefreshtoken_init(const br_detector **out, char **error)
{
    static const char *const secret_prefix[] = {"salesforce", "consumer", "secret"};
    if (error) *error = NULL;
    if (!out) return salesforce_fail(error, "invalid SalesforceRefreshToken detector output");
    *out = NULL;
    if (!salesforce_detector.state) {
        salesforce_patterns *patterns = calloc(1, sizeof(*patterns));
        if (!patterns) return salesforce_fail(error, "out of memory compiling SalesforceRefreshToken patterns");
        if (br_regex_compile("(?i)\\b(5AEP861[a-zA-Z0-9._=]{80,})\\b", &patterns->token, error) != 0 ||
            br_regex_compile("\\b(3MVG9[0-9a-zA-Z._+/=]{80,251})", &patterns->key, error) != 0 ||
            br_regex_compile_prefixed(secret_prefix, 3, "\\b([A-Za-z0-9+/=.]{64}|[0-9]{19})\\b",
                                      &patterns->secret, error) != 0) {
            br_regex_free(patterns->token);
            br_regex_free(patterns->key);
            br_regex_free(patterns->secret);
            free(patterns);
            return -1;
        }
        salesforce_detector.state = patterns;
    }
    *out = &salesforce_detector;
    return 0;
}
