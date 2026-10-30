/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/typeform/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char typeform_url[] = "https://api.typeform.com/me";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_error(br_result *result, const char *message, char **error)
{
    /* NULL diagnostic is a checked no-op, but a known error still reaches the setter. */
    if (br_result_set_verification_error(result, message, NULL, 0) != 0)
        return fail(error, "cannot record Typeform verification error");
    return 0;
}

static int unexpected_status(br_result *result, const char *format, int status, char **error)
{
    char message[64];
    int n = snprintf(message, sizeof(message), format, status);
    if (n < 0 || (size_t)n >= sizeof(message))
        return fail(error, "cannot format Typeform status");
    return set_error(result, message, error);
}

/* Both versions pass no secrets to SetVerificationError. A transport error that
 * echoes the bearer token stays intact. */
static int round_trip(const br_scan_ctx *ctx, const char *key, br_result *result,
                      br_http_response *response, int *sent_ok, char **error)
{
    if (sent_ok) *sent_ok = 0;
    if (!ctx) return set_error(result, "net/http: nil Context", error);
    char authorization[80];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization))
        return fail(error, "cannot format Typeform authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = typeform_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 370,
    };
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, response, &send_error);
    if (sent != 0) {
        int rc = set_error(result, send_error, error);
        free(send_error);
        return rc;
    }
    free(send_error);
    if (sent_ok) *sent_ok = 1;
    return 0;
}

static int verify_v1(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_http_response response = {0};
    int sent_ok = 0;
    int rc = round_trip(ctx, key, result, &response, &sent_ok, error);
    /* Body is drained and ignored. 403 is determinate, unlike a generic 4xx.
     * A failed send stays failed even when the diagnostic and status are empty. */
    if (!rc && sent_ok) {
        if (response.status == 200) result->verified = true;
        else if (response.status != 401 && response.status != 403)
            rc = unexpected_status(result, "unexpected status code: %d", response.status, error);
    }
    br_http_release(ctx, &response);
    return rc;
}

typedef struct {
    char *data;
    size_t len;
} typeform_text;

typedef struct {
    typeform_text user_id, email, alias, language;
    char *cause;
    int failed;
    int rc;
} typeform_fields;

static int typeform_type_cause_real(br_json *value, const char *field, char **cause)
{
    return br_json_type_cause(value, field, "string", cause);
}

static int (*typeform_type_cause)(br_json *, const char *, char **) = typeform_type_cause_real;

static int copy_json_text(br_json *value, typeform_text *slot)
{
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->data);
    slot->data = copy;
    slot->len = text.len;
    return 0;
}

static int typeform_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    typeform_fields *fields = user;
    const char *field = NULL;
    typeform_text *slot = NULL;
    if (br_json_field_name(name, "user_id")) { field = "TypeFormResponse.user_id"; slot = &fields->user_id; }
    else if (br_json_field_name(name, "email")) { field = "TypeFormResponse.email"; slot = &fields->email; }
    else if (br_json_field_name(name, "alias")) { field = "TypeFormResponse.alias"; slot = &fields->alias; }
    else if (br_json_field_name(name, "language")) { field = "TypeFormResponse.language"; slot = &fields->language; }
    else return 0;
    enum json_type kind = json_object_get_type(value);
    if (kind == json_type_null) return 0; /* null does not clear a prior string */
    if (kind != json_type_string) {
        char *cause = NULL;
        int typed = typeform_type_cause(value, field, &cause);
        if (typed < 0) { free(cause); fields->rc = -1; return -1; }
        if (typed > 0 || cause) {
            if (!fields->failed) { fields->failed = 1; fields->cause = cause; fields->rc = 1; }
            else free(cause);
        } else free(cause);
        return 0;
    }
    if (copy_json_text(value, slot) != 0) { fields->rc = -1; return -1; }
    return 0;
}

static int put_extra(br_result *result, const char *name, const char *text, size_t len, char **error)
{
    br_json *value = json_object_new_string_len(text ? text : "", (int)len);
    if (!value) return fail(error, "cannot create Typeform metadata");
    if (json_object_object_add(result->extra_data, name, value) == 0) return 0;
    json_object_put(value);
    return fail(error, "cannot create Typeform metadata");
}

static int decode_v2(br_slice body, const char *read_error, br_result *result, char **error)
{
    br_json *value = NULL;
    char *cause = NULL;
    size_t end = 0;
    int decoded = br_json_first_document(body, read_error, &value, &end, &cause);
    if (decoded < 0 || decoded > 1) { json_object_put(value); free(cause); return fail(error, "cannot decode Typeform response"); }
    if (decoded == 1) {
        int rc = set_error(result, cause, error);
        free(cause);
        return rc;
    }
    free(cause);
    /* JSON null decodes to a nil *TypeFormResponse: verified, no extra data. */
    if (!value || json_object_get_type(value) == json_type_null) {
        json_object_put(value);
        result->verified = true;
        return 0;
    }
    if (json_object_get_type(value) != json_type_object) {
        char *type_cause = NULL;
        int typed = br_json_type_cause(value, NULL, "typeform.TypeFormResponse", &type_cause);
        json_object_put(value);
        if (typed != 0) return fail(error, "cannot record Typeform verification error");
        int rc = set_error(result, type_cause, error);
        free(type_cause);
        return rc;
    }
    json_object_put(value);
    typeform_fields fields = {0};
    int walked = br_json_each_member((br_slice){body.data, end}, typeform_member, &fields);
    if (walked != 0 || fields.rc < 0) {
        free(fields.user_id.data); free(fields.email.data); free(fields.alias.data);
        free(fields.language.data); free(fields.cause);
        return fail(error, "cannot decode Typeform response");
    }
    if (fields.rc > 0) {
        int rc = set_error(result, fields.cause, error);
        free(fields.user_id.data); free(fields.email.data); free(fields.alias.data);
        free(fields.language.data); free(fields.cause);
        return rc;
    }
    result->extra_data = json_object_new_object();
    int rc = result->extra_data ? 0 : fail(error, "cannot create Typeform metadata");
    if (!rc) rc = put_extra(result, "UserId", fields.user_id.data, fields.user_id.len, error);
    if (!rc) rc = put_extra(result, "Email", fields.email.data, fields.email.len, error);
    if (!rc) rc = put_extra(result, "Alias", fields.alias.data, fields.alias.len, error);
    if (!rc) rc = put_extra(result, "Language", fields.language.data, fields.language.len, error);
    free(fields.user_id.data); free(fields.email.data); free(fields.alias.data); free(fields.language.data);
    if (!rc) result->verified = true;
    return rc;
}

static int verify_v2(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    /* Scanner.client is not a second code path. A set client and the package
     * default both reach the injected transport. */
    br_http_response response = {0};
    int sent_ok = 0;
    int rc = round_trip(ctx, key, result, &response, &sent_ok, error);
    if (!rc && sent_ok) {
        if (response.status == 200)
            rc = decode_v2(response.body, response.body_error, result, error);
        else if (response.status != 401 && response.status != 403)
            rc = unexpected_status(result, "unexpected status code %d", response.status, error);
    }
    br_http_release(ctx, &response);
    return rc;
}

typedef int (*typeform_verify_fn)(const br_scan_ctx *, const char *, br_result *, char **);

static int scan_typeform(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, typeform_verify_fn check, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Typeform scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op: neither class contains whitespace. Keep every
         * occurrence. The v1 "ignore duplicate" fixture is outside the 40-byte
         * prefix window, not a uniqueness filter. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Typeform result");
        else if (verify && check(ctx, keys.items[i], &result, error) != 0)
            rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append Typeform result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static int scan_v1(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    return scan_typeform(detector, ctx, verify, input, out, verify_v1, error);
}

static int scan_v2(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    return scan_typeform(detector, ctx, verify, input, out, verify_v2, error);
}

static const char *const typeform_v1_keywords[] = {"typeform"};
static const char *const typeform_v2_keywords[] = {"tfp_"};
static br_regex *typeform_v2_regex;
static br_detector typeform_v1 = {
    .type = 370, .version = 1, .name = "Typeform", .custom_name = "",
    .description = "Typeform is a service for creating forms and surveys. Typeform API keys can be used to access and manage forms and responses.",
    .keywords = typeform_v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_v1,
};
static br_detector typeform_v2 = {
    .type = 370, .version = 2, .name = "Typeform", .custom_name = "",
    .description = "Typeform is a service for creating forms and surveys. Typeform API keys can be used to access and manage forms and responses.",
    .keywords = typeform_v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_v2,
};

int br_typeform_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Typeform detector output");
    *out = NULL;
    if (br_key_pattern_init(&typeform_v1, "\\b([0-9A-Za-z]{44})\\b", error) != 0) return -1;
    *out = &typeform_v1;
    return 0;
}

int br_typeform_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Typeform detector output");
    *out = NULL;
    if (!typeform_v2_regex &&
        br_regex_compile("\\b(tfp_[a-zA-Z0-9_]{40,59})\\b", &typeform_v2_regex, error) != 0)
        return -1;
    typeform_v2.state = typeform_v2_regex;
    *out = &typeform_v2;
    return 0;
}
