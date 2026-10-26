/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, azure_entra/serviceprincipal/sp.go and
 * serviceprincipal/v1/spv1.go, v2/spv2.go. V1 delegates processing to V2. */
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

static br_regex *legacy_pattern, *modern_pattern;

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

/* Go url.QueryEscape, not path escaping or curl's treatment of spaces. */
static int query_escape(const char *value, char **out)
{
    size_t len = strlen(value);
    if (len > (SIZE_MAX - 1) / 3) return -1;
    *out = malloc(len * 3 + 1);
    if (!*out) return -1;
    static const char hex[] = "0123456789ABCDEF";
    size_t at = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)value[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') (*out)[at++] = (char)c;
        else if (c == ' ') (*out)[at++] = '+';
        else { (*out)[at++] = '%'; (*out)[at++] = hex[c >> 4]; (*out)[at++] = hex[c & 15]; }
    }
    (*out)[at] = '\0';
    return 0;
}

typedef struct { bool success; br_json *access, *code, *description; char *cause; } http_fields;
static int read_http_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    http_fields *fields = user;
    br_json **slot = NULL;
    const char *field = NULL;
    if (fields->success) {
        if (br_json_field_name(name, "access_token")) { slot = &fields->access; field = "TokenOkResponse.access_token"; }
    } else if (br_json_field_name(name, "error")) { slot = &fields->code; field = "TokenErrResponse.error"; }
    else if (br_json_field_name(name, "error_description")) { slot = &fields->description; field = "TokenErrResponse.error_description"; }
    if (!slot || !value) return 0; /* Null does not reset a Go struct string. */
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
            rc = br_json_type_cause(root, NULL, fields->success ? "serviceprincipal.TokenOkResponse" : "serviceprincipal.TokenErrResponse",
                                    &fields->cause) ? -1 : 1;
        else rc = br_json_each_member((br_slice){response->body.data, end}, read_http_field, fields);
    }
    json_object_put(root);
    return rc;
}

static int project_application(br_slice access, br_json *extra, char **error)
{
    br_azure_entra_jwt_fields fields = {0};
    int rc = br_azure_entra_jwt_read(access, &fields, error);
    if (rc > 0) rc = fail(error, "unsupported upstream panic: Azure service principal JWT Claims is nil");
    else if (!rc && fields.token_present && fields.app) {
        br_slice text;
        if (json_object_is_type(fields.app, json_type_string)) text = br_json_text(fields.app);
        else if (json_object_is_type(fields.app, json_type_boolean)) {
            bool yes = json_object_get_boolean(fields.app);
            text = (br_slice){(const unsigned char *)(yes ? "true" : "false"), yes ? 4 : 5};
        } else {
            rc = fail(error, "unsupported: Azure service principal JWT claim formatting");
            goto cleanup;
        }
        rc = put_text(extra, "application", text); /* Empty string IS included. */
    }
cleanup:
    /* Missing/null application is omitted; email/upn/unique_name are unused. */
    br_azure_entra_jwt_clear(&fields);
    return rc;
}

typedef enum { OTHER, VALID, CONDITIONAL, SECRET_INVALID, SECRET_EXPIRED, TENANT_MISSING, CLIENT_MISSING } verify_state;
typedef struct { verify_state state; br_json *extra; char *cause; } verified_pair;
static void clear_pair(verified_pair *pair)
{
    json_object_put(pair->extra); free(pair->cause); *pair = (verified_pair){0};
}

static bool starts(br_slice value, const char *prefix)
{
    size_t len = strlen(prefix);
    return value.len >= len && !memcmp(value.data, prefix, len);
}

static int verify_credentials(const br_scan_ctx *ctx, const char *tenant, const char *client,
                                const char *secret, verified_pair *out, char **error)
{
    /* The source suppresses request-creation errors, unlike refresh tokens. */
    if (!ctx) return 0;
    char *escaped = NULL, *body = NULL, *url = NULL, *send_error = NULL;
    if (query_escape(secret, &escaped) ||
        textf(&body, "client_id=%s&client_secret=%s&grant_type=client_credentials&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default", client, escaped) ||
        textf(&url, "https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)) {
        free(escaped); free(body); free(url);
        return fail(error, "out of memory constructing Azure service principal request");
    }
    char length[32]; snprintf(length, sizeof(length), "%zu", strlen(body));
    const br_header headers[] = {{"Accept", "application/json"}, {"Content-Type", "application/x-www-form-urlencoded"}, {"Content-Length", length}};
    const br_http_request request = {.method = "POST", .url = url, .headers = headers, .nheaders = 3,
        .body = {(const unsigned char *)body, strlen(body)}, .profile = BR_HTTP_SANE, .detector_type = 3};
    br_http_response response = {0};
    http_fields fields = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error)) {
        out->cause = send_error; send_error = NULL;
        if (!out->cause) { out->cause = strdup("HTTP transport failed"); if (!out->cause) rc = -1; }
    } else {
        fields.success = response.status == 200;
        int decoded = decode_http(&response, &fields); /* All non-200 decode first. */
        if (decoded < 0) rc = -1;
        else if (decoded) { out->cause = fields.cause; fields.cause = NULL; }
        else if (response.status == 200) {
            out->extra = json_object_new_object();
            if (!out->extra || put_literal(out->extra, "rotation_guide", "https://howtorotate.com/docs/tutorials/azure/") ||
                put_literal(out->extra, "tenant", tenant) || put_literal(out->extra, "client", client)) rc = -1;
            else rc = project_application(br_json_text(fields.access), out->extra, error);
            if (!rc) out->state = VALID;
        } else if (response.status == 400 || response.status == 401) {
            br_slice description = br_json_text(fields.description);
            if (starts(description, "AADSTS53003:")) {
                out->state = CONDITIONAL;
                out->cause = strdup("access blocked by Conditional Access policies (AADSTS53003)");
                if (!out->cause) rc = -1;
            } else if (starts(description, "AADSTS700016:")) out->state = CLIENT_MISSING;
            else if (starts(description, "AADSTS7000215:")) out->state = SECRET_INVALID;
            else if (starts(description, "AADSTS7000222:")) out->state = SECRET_EXPIRED;
            else if (starts(description, "AADSTS90002:")) out->state = TENANT_MISSING;
            else rc = textf(&out->cause, "unexpected error '%s': %s", (const char *)br_json_text(fields.code).data,
                            (const char *)description.data);
        } else rc = textf(&out->cause, "unexpected HTTP response status %d", response.status);
    }
    br_http_release(ctx, &response);
    json_object_put(fields.access); json_object_put(fields.code); json_object_put(fields.description); free(fields.cause);
    free(send_error); free(url); free(body); free(escaped);
    if (rc && error && !*error) return fail(error, "out of memory decoding Azure service principal response");
    return rc;
}

static int create_result(const char *secret, const char *client, const char *tenant, const verified_pair *pair, br_result *out)
{
    if (br_finding_key(out, 3, secret, "key")) return -1;
    out->redacted = malloc(9);
    if (!out->redacted) return -1;
    memcpy(out->redacted, secret, 5); memcpy(out->redacted + 5, "...", 4);
    if (pair) {
        out->verified = pair->state == VALID;
        out->extra_data = json_object_get(pair->extra);
        br_slice redact = {(const unsigned char *)secret, strlen(secret)};
        if (br_result_set_verification_error(out, pair->cause, &redact, 1)) return -1;
    }
    if (*client && *tenant) {
        char *raw = NULL;
        /* Deliberately literal, including v1 backslashes: this is not a JSON
         * serialization API. Source RawV2 can itself contain invalid JSON. */
        if (textf(&raw, "{\"clientSecret\":\"%s\",\"clientId\":\"%s\",\"tenantId\":\"%s\"}", secret, client, tenant)) return -1;
        out->raw_v2 = (br_bytes){(unsigned char *)raw, strlen(raw)};
    }
    return 0;
}

static int matched(void *user, const br_span *groups, size_t count)
{
    (void)groups; (void)count;
    *(bool *)user = true;
    return 0;
}

static int scan_principal(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !*(br_regex *const *)detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure service principal scan arguments");
    size_t original_len = out->len;
    br_captures matches = {0}, secrets = {0}, clients = {0}, tenants = {0};
    bool *deleted_clients = NULL, *deleted_tenants = NULL, *invalid = NULL;
    int rc = br_captures_find(*(br_regex *const *)detector->state, input, &matches, true, error);
    for (size_t i = 0; !rc && i < matches.len; ++i) {
        bool modern = false;
        if (detector->version == 1) rc = br_regex_each(modern_pattern, br_captures_at(&matches, i), matched, &modern, error);
        if (!rc && !modern) rc = br_captures_push(&secrets, br_captures_at(&matches, i), true, error);
    }
    if (rc || !secrets.len) goto cleanup;
    rc = br_azure_entra_find_ids(input, &clients, &tenants, error);
    if (rc || (detector->version == 1 && !clients.len)) goto cleanup;
    if (clients.len && tenants.len > SIZE_MAX / clients.len) { rc = fail(error, "Azure service principal pairing state too large"); goto cleanup; }
    deleted_clients = calloc(clients.len ? clients.len : 1, sizeof(*deleted_clients));
    deleted_tenants = calloc(tenants.len ? tenants.len : 1, sizeof(*deleted_tenants));
    size_t cells = clients.len * tenants.len;
    invalid = calloc(cells ? cells : 1, sizeof(*invalid));
    if (!deleted_clients || !deleted_tenants || !invalid) { rc = fail(error, "out of memory tracking Azure service principal pairs"); goto cleanup; }
    size_t live_clients = clients.len, live_tenants = tenants.len;
    for (size_t s = 0; !rc && s < secrets.len; ++s) {
        const char *client = "", *tenant = "";
        bool finalized = false;
        verified_pair pair = {0};
        for (size_t c = 0; !rc && !finalized && c < clients.len; ++c) {
            if (deleted_clients[c]) continue;
            client = clients.items[c];
            for (size_t t = 0; !rc && !finalized && t < tenants.len; ++t) {
                if (deleted_tenants[t]) continue;
                tenant = tenants.items[t];
                if (invalid[t * clients.len + c] || !verify) continue;
                bool exists = false;
                /* Unlike refresh tokens, every eligible pair checks discovery
                 * through the shared cache, even after earlier positive pairs. */
                rc = br_azure_entra_tenant_exists(ctx, 3, tenant, &exists, error);
                if (rc) break;
                if (!exists) { deleted_tenants[t] = true; --live_tenants; continue; }
                for (size_t other = 0; other < clients.len; ++other) {
                    if (!deleted_clients[other] && !strcmp(clients.items[other], tenant)) {
                        deleted_clients[other] = true; --live_clients;
                    }
                }
                /* Deleting the CURRENT client does not cancel this pair or
                 * its remaining inner loop. Go range has already assigned it. */
                rc = verify_credentials(ctx, tenant, client, secrets.items[s], &pair, error);
                if (rc) break;
                if (pair.state == TENANT_MISSING) { deleted_tenants[t] = true; --live_tenants; }
                else if (pair.state == CLIENT_MISSING) invalid[t * clients.len + c] = true;
                else if (pair.state == SECRET_INVALID) { clear_pair(&pair); break; } /* NEXT client, same secret. */
                else if (pair.state == SECRET_EXPIRED || pair.state == VALID || (live_clients == 1 && live_tenants == 1)) finalized = true;
                if (!finalized) clear_pair(&pair);
            }
        }
        if (!finalized) {
            if (live_clients != 1) client = "";
            if (live_tenants != 1) tenant = "";
        }
        br_result result = {0};
        if (!rc) rc = create_result(secrets.items[s], client, tenant, finalized ? &pair : NULL, &result);
        if (!rc) rc = br_results_push(out, &result);
        br_result_clear(&result); clear_pair(&pair);
        if (rc && error && !*error) rc = fail(error, "out of memory creating Azure service principal result");
    }
cleanup:
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(deleted_clients); free(deleted_tenants); free(invalid);
    br_captures_clear(&matches); br_captures_clear(&secrets); br_captures_clear(&clients); br_captures_clear(&tenants);
    return rc;
}

static const char *const legacy_keywords[] = {"azure", "az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"};
static const char *const modern_keywords[] = {"q~"};
#define PRINCIPAL_DESCRIPTION "Azure is a cloud service offering a wide range of services including compute, analytics, storage, and networking. Azure credentials can be used to access and manage these services."
static const br_detector legacy = {
    .type = 3, .version = 1, .name = "Azure", .custom_name = "", .description = PRINCIPAL_DESCRIPTION,
    .keywords = legacy_keywords, .nkeywords = 6, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &legacy_pattern, .scan = scan_principal,
};
static const br_detector modern = {
    .type = 3, .version = 2, .name = "Azure", .custom_name = "", .description = PRINCIPAL_DESCRIPTION,
    .keywords = modern_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &modern_pattern, .scan = scan_principal,
};
#undef PRINCIPAL_DESCRIPTION

static int init(const br_detector **out, bool v1, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Azure service principal detector output");
    *out = NULL;
    if (br_azure_entra_common_init(error)) return -1;
    if (!modern_pattern && br_regex_compile("(?:[^a-zA-Z0-9_~.-]|\\A)([a-zA-Z0-9_~.-]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\\z)", &modern_pattern, error)) return -1;
#define LEGACY_CHARS "A-Za-z0-9!#$%&()*+,\\-./:;<=>?@[\\\\\\]^_{|}~"
    if (v1 && !legacy_pattern && br_regex_compile("(?i)(?:secret|password| -p[ =]).{0,80}[^" LEGACY_CHARS "]([" LEGACY_CHARS "]{31,34})[^" LEGACY_CHARS "]", &legacy_pattern, error)) return -1;
#undef LEGACY_CHARS
    *out = v1 ? &legacy : &modern;
    return 0;
}

int br_azure_entra_serviceprincipal_v1_init(const br_detector **out, char **error) { return init(out, true, error); }
int br_azure_entra_serviceprincipal_v2_init(const br_detector **out, char **error) { return init(out, false, error); }
