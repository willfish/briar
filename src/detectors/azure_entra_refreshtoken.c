/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, azure_entra/refreshtoken/refreshtoken.go.
 * JWT projection follows github.com/golang-jwt/jwt/v5 v5.2.3 parser.go (MIT,
 * Copyright Dave Grijalva and golang-jwt maintainers). No JWT signature is
 * verified here: the source ignores Parse errors and consumes only Claims. */
#include "detectors.h"
#include "azure_entra_common.h"
#include "azure_entra_jwt.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char default_client[] = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
static const char default_tenant[] = "common";
static br_regex *token_pattern;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int textf(char **out, const char *format, ...)
{
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int len = vsnprintf(NULL, 0, format, args);
    va_end(args);
    *out = len < 0 ? NULL : malloc((size_t)len + 1);
    if (*out) vsnprintf(*out, (size_t)len + 1, format, copy);
    va_end(copy);
    return *out ? 0 : -1;
}

static int put_text(br_json *object, const char *name, br_slice value)
{
    if (value.len > INT_MAX) return -1;
    br_json *text = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!text) return -1;
    if (!json_object_object_add(object, name, text)) return 0;
    json_object_put(text);
    return -1;
}

static int put_literal(br_json *object, const char *name, const char *value)
{
    return put_text(object, name, (br_slice){(const unsigned char *)value, strlen(value)});
}

typedef struct { br_json *first, *second; bool success; char *cause; } http_fields;
static int read_http_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    http_fields *fields = user;
    br_json **slot = NULL;
    const char *field = NULL;
    if (br_json_field_name(name, fields->success ? "scope" : "error")) {
        slot = &fields->first;
        field = fields->success ? "successResponse.scope" : "errorResponse.error";
    } else if (br_json_field_name(name, fields->success ? "access_token" : "error_description")) {
        slot = &fields->second;
        field = fields->success ? "successResponse.access_token" : "errorResponse.error_description";
    }
    if (!slot || !value) return 0; /* Null does not reset a Go string. */
    if (!json_object_is_type(value, json_type_string))
        return br_json_type_cause(value, field, "string", &fields->cause) ? -1 : 1;
    json_object_put(*slot); *slot = json_object_get(value);
    return 0;
}

static int decode_http(const br_http_response *response, http_fields *fields)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &fields->cause);
    if (!rc && root) {
        if (!json_object_is_type(root, json_type_object))
            rc = br_json_type_cause(root, NULL, fields->success ? "refreshtoken.successResponse" : "refreshtoken.errorResponse",
                                    &fields->cause) ? -1 : 1;
        else rc = br_json_each_member((br_slice){response->body.data, end}, read_http_field, fields);
    }
    json_object_put(root);
    return rc;
}

/* Only the source's observed string/nil/bool formatting is reproduced. Numeric
 * and aggregate fmt.Sprint output is an explicit guard, not JSON stringification. */
static int print_claim(br_json *value, br_slice *text, char **error)
{
    if (!value) { *text = (br_slice){(const unsigned char *)"<nil>", 5}; return 0; }
    if (json_object_is_type(value, json_type_string)) { *text = br_json_text(value); return 0; }
    if (json_object_is_type(value, json_type_boolean)) {
        bool yes = json_object_get_boolean(value);
        *text = (br_slice){(const unsigned char *)(yes ? "true" : "false"), yes ? 4 : 5};
        return 0;
    }
    return fail(error, "unsupported: Azure refresh JWT claim formatting");
}

static int project_claims(br_slice access_token, br_json *extra, char **error)
{
    br_azure_entra_jwt_fields fields = {0};
    char *cause = NULL;
    int rc = br_azure_entra_jwt_read(access_token, &fields, &cause);
    free(cause);
    if (rc < 0) goto resource;
    if (rc) {
        rc = fail(error, "unsupported upstream panic: Azure refresh JWT Claims is nil");
        goto cleanup;
    }
    if (!fields.token_present) goto cleanup;
    br_slice text;
    rc = print_claim(fields.app, &text, error);
    if (!rc && text.len) rc = put_text(extra, "Application", text);
    if (!rc && (fields.email || fields.upn)) {
        rc = print_claim(fields.email ? fields.email : fields.upn, &text, error);
        if (!rc) rc = put_text(extra, "User", text);
    } else if (!rc && json_object_is_type(fields.unique_name, json_type_boolean) && json_object_get_boolean(fields.unique_name))
        rc = put_literal(extra, "User", "true");
    if (rc && error && !*error) goto resource;
    goto cleanup;
resource:
    rc = fail(error, "out of memory projecting Azure refresh JWT claims");
cleanup:
    br_azure_entra_jwt_clear(&fields);
    return rc;
}

typedef enum { TRY_NEXT, VALID, TENANT_MISSING, CLIENT_MISSING, EXPIRED, REVOKED, UNEXPECTED } exchange_state;
typedef struct { exchange_state state; br_json *extra; char *cause; } exchange_result;

static bool starts(br_slice value, const char *prefix)
{
    size_t len = strlen(prefix);
    return value.len >= len && !memcmp(value.data, prefix, len);
}

static int exchange_token(const br_scan_ctx *ctx, const char *token, const char *client, const char *tenant,
                            exchange_result *out, char **error)
{
    out->state = UNEXPECTED;
    if (!ctx) { out->cause = strdup("net/http: nil Context"); return out->cause ? 0 : -1; }
    char *url = NULL, *body = NULL, *send_error = NULL;
    if (textf(&url, "https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant) ||
        textf(&body, "client_id=%s&grant_type=refresh_token&refresh_token=%s&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default", client, token)) {
        free(url); free(body);
        return fail(error, "out of memory constructing Azure refresh request");
    }
    /* All variable form bytes come from ASCII UUID/refresh-token patterns;
     * their alphabet is URL-query safe. The fixed scope is QueryEscaped. */
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {.method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, strlen(body)}, .profile = BR_HTTP_SANE, .detector_type = 1013};
    br_http_response response = {0};
    http_fields fields = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error)) {
        out->cause = send_error; send_error = NULL;
        if (!out->cause) { out->cause = strdup("HTTP transport failed"); if (!out->cause) rc = -1; }
    } else {
        fields.success = response.status == 200;
        int decoded = decode_http(&response, &fields); /* Even 401 needs typed JSON. */
        if (decoded < 0) rc = -1;
        else if (decoded) { out->cause = fields.cause; fields.cause = NULL; }
        else if (response.status == 200) {
            out->extra = json_object_new_object();
            if (!out->extra || put_literal(out->extra, "Tenant", tenant) || put_literal(out->extra, "Client", client) ||
                put_text(out->extra, "Scope", br_json_text(fields.first))) rc = -1;
            else rc = project_claims(br_json_text(fields.second), out->extra, error);
            if (!rc) out->state = VALID;
        } else if (response.status == 400) {
            br_slice description = br_json_text(fields.second);
            if (starts(description, "AADSTS70008:") || starts(description, "AADSTS700082:") || starts(description, "AADSTS70043:")) out->state = EXPIRED;
            else if (starts(description, "AADSTS50173:")) out->state = REVOKED;
            else if (starts(description, "AADSTS700016:")) out->state = CLIENT_MISSING;
            else if (starts(description, "AADSTS90002:")) out->state = TENANT_MISSING;
            else if (starts(description, "AADSTS9002313:")) out->state = TRY_NEXT;
            else rc = textf(&out->cause, "unexpected error '%s': %s", (const char *)br_json_text(fields.first).data,
                            (const char *)description.data);
        } else if (response.status == 401) out->state = TRY_NEXT;
        else rc = textf(&out->cause, "unexpected HTTP response status %d", response.status);
    }
    br_http_release(ctx, &response);
    json_object_put(fields.first); json_object_put(fields.second); free(fields.cause);
    free(send_error); free(body); free(url);
    if (rc && error && !*error) return fail(error, "out of memory decoding Azure refresh response");
    return rc;
}

static int create_result(const char *token, const char *client, const char *tenant, const exchange_result *exchange, br_result *out)
{
    if (br_finding_key(out, 1013, token, "key")) return -1;
    if (exchange) {
        out->verified = exchange->state == VALID;
        out->extra_data = json_object_get(exchange->extra);
        br_slice redact = {(const unsigned char *)token, strlen(token)};
        if (br_result_set_verification_error(out, exchange->cause, &redact, 1)) return -1;
    }
    if (*client && *tenant) {
        char *raw = NULL;
        if (textf(&raw, "{\"refreshToken\":\"%s\",\"clientId\":\"%s\",\"tenantId\":\"%s\"}", token, client, tenant)) return -1;
        out->raw_v2 = (br_bytes){(unsigned char *)raw, strlen(raw)};
    }
    return 0;
}

static int scan_refresh(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !*(br_regex *const *)detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure refresh token scan arguments");
    size_t original_len = out->len;
    br_captures tokens = {0}, clients = {0}, tenants = {0};
    bool *deleted = NULL, *valid = NULL, *invalid = NULL;
    int rc = br_captures_find(*(br_regex *const *)detector->state, input, &tokens, true, error);
    bool found = false;
    for (size_t i = 0; !rc && i < tokens.len; ++i)
        if (br_ascii_shannon_entropy(br_captures_at(&tokens, i)) >= 4.0) { found = true; break; }
    if (rc || !found) goto cleanup;
    rc = br_azure_entra_find_ids(input, &clients, &tenants, error);
    if (!rc && !clients.len) rc = br_captures_push(&clients, (br_slice){(const unsigned char *)default_client, sizeof(default_client) - 1}, true, error);
    if (!rc && !tenants.len) rc = br_captures_push(&tenants, (br_slice){(const unsigned char *)default_tenant, sizeof(default_tenant) - 1}, true, error);
    if (rc) goto cleanup;
    if (tenants.len > SIZE_MAX / clients.len) { rc = fail(error, "Azure refresh pairing state too large"); goto cleanup; }
    deleted = calloc(tenants.len, sizeof(*deleted)); valid = calloc(tenants.len, sizeof(*valid));
    invalid = calloc(tenants.len * clients.len, sizeof(*invalid));
    if (!deleted || !valid || !invalid) { rc = fail(error, "out of memory tracking Azure refresh pairs"); goto cleanup; }
    size_t remaining_tenants = tenants.len;
    for (size_t token_at = 0; !rc && token_at < tokens.len; ++token_at) {
        const char *token = tokens.items[token_at];
        if (br_ascii_shannon_entropy(br_captures_at(&tokens, token_at)) < 4.0) continue;
        const char *client = "", *tenant = "";
        bool finalized = false;
        exchange_result exchange = {0};
        for (size_t c = 0; !rc && !finalized && c < clients.len; ++c) {
            client = clients.items[c];
            for (size_t t = 0; !rc && !finalized && t < tenants.len; ++t) {
                if (deleted[t]) continue;
                tenant = tenants.items[t];
                if (invalid[t * clients.len + c] || !verify) continue;
                if (!valid[t]) {
                    bool exists = false;
                    rc = br_azure_entra_tenant_exists(ctx, 1013, tenant, &exists, error);
                    if (rc) break;
                    if (!exists) { deleted[t] = true; --remaining_tenants; continue; }
                    valid[t] = true;
                }
                rc = exchange_token(ctx, token, client, tenant, &exchange, error);
                if (rc) break;
                if (exchange.state == TENANT_MISSING) { deleted[t] = true; --remaining_tenants; }
                else if (exchange.state == CLIENT_MISSING) invalid[t * clients.len + c] = true;
                else if (exchange.state != TRY_NEXT) finalized = true;
                if (!finalized) { json_object_put(exchange.extra); free(exchange.cause); exchange = (exchange_result){0}; }
            }
        }
        bool actual_pair = finalized && (exchange.state == VALID || exchange.state == UNEXPECTED);
        if (!actual_pair) {
            if (clients.len != 1 || !strcmp(client, default_client)) client = "";
            if (remaining_tenants != 1 || !strcmp(tenant, default_tenant)) tenant = "";
        }
        br_result result = {0};
        if (!rc) rc = create_result(token, client, tenant, actual_pair ? &exchange : NULL, &result);
        if (!rc) rc = br_results_push(out, &result);
        br_result_clear(&result); json_object_put(exchange.extra); free(exchange.cause);
        if (rc && error && !*error) rc = fail(error, "out of memory creating Azure refresh token result");
    }
cleanup:
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(deleted); free(valid); free(invalid);
    br_captures_clear(&tokens); br_captures_clear(&clients); br_captures_clear(&tenants);
    return rc;
}

static const char *const keywords[] = {"0.A", "1.A"};
static const br_detector refresh_detector = {
    .type = 1013, .version = 0, .name = "AzureRefreshToken", .custom_name = "",
    .description = "Azure Entra ID refresh tokens provide long-lasting access to an account.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = 2048, .start_offset = 4096, .max_credential_span = 1024,
    .state = &token_pattern, .scan = scan_refresh,
};

int br_azure_entra_refreshtoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Azure refresh token detector output");
    *out = NULL;
    if (br_azure_entra_common_init(error)) return -1;
    if (!token_pattern && br_regex_compile("(\\b[01]\\.A[\\w-]{50,}(?:\\.\\d)?\\.Ag[\\w-]{250,}(?:\\.A[\\w-]{200,})?)", &token_pattern, error)) return -1;
    *out = &refresh_detector;
    return 0;
}
