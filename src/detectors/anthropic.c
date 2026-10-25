/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/anthropic/anthropic.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *type, *message; } api_error_fields;

enum { MAX_ERROR_BODY_SIZE = 4096 };

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int read_error_field(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    api_error_fields *fields = user;
    br_json **field = NULL;
    if (br_json_field_name(name, "type")) field = &fields->type;
    else if (br_json_field_name(name, "message")) field = &fields->message;
    if (!field || !value) return 0; /* JSON null leaves a Go string unchanged. */
    if (!json_object_is_type(value, json_type_string)) return 1;
    json_object_put(*field);
    *field = json_object_get(value);
    return 0;
}

static int read_error_envelope(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    if (!br_json_field_name(name, "error") || !value) return 0;
    if (!json_object_is_type(value, json_type_object)) return 1;
    /* Repeated error objects merge into the same struct. Visit their original
     * bytes so earlier duplicate string assignments and nulls are not lost. */
    return br_json_each_member(encoded_value, read_error_field, user);
}

static int api_error(const br_http_response *response, char **cause)
{
    char status[80];
    snprintf(status, sizeof(status), "unexpected HTTP response status %d", response->status);
    br_slice body = response->body;
    if (body.len > MAX_ERROR_BODY_SIZE) body.len = MAX_ERROR_BODY_SIZE;
    api_error_fields fields = {0};
    br_json *root = NULL;
    char *decode_cause = NULL;
    bool enrich = false;
    int rc = 0;
    /* LimitReader hides failures after its cap. Earlier read failures suppress
     * enrichment even when the bytes already contain a complete JSON object. */
    if (!response->body_error || response->body.len >= MAX_ERROR_BODY_SIZE) {
        int decoded = br_json_document(body, &root, &decode_cause);
        if (decoded < 0) { rc = -1; goto done; }
        if (!decoded && root && json_object_is_type(root, json_type_object)) {
            int visited = br_json_each_member(body, read_error_envelope, &fields);
            if (visited < 0) { rc = -1; goto done; }
            enrich = !visited && br_json_text(fields.type).len != 0;
        }
    }
    br_slice type = br_json_text(fields.type), message = br_json_text(fields.message);
    size_t status_len = strlen(status);
    size_t len = status_len + (enrich ? type.len + message.len + 5 : 0);
    *cause = malloc(len + 1);
    if (!*cause) { rc = -1; goto done; }
    char *at = *cause;
    memcpy(at, status, status_len);
    at += status_len;
    if (enrich) {
        memcpy(at, " (", 2); at += 2;
        memcpy(at, type.data, type.len); at += type.len;
        memcpy(at, ": ", 2); at += 2;
        memcpy(at, message.data, message.len); at += message.len;
        *at++ = ')';
    }
    *at = '\0';
    /* JSON string bytes are retained here; ABI1's error setter is C-string based. */
done:
    json_object_put(fields.type);
    json_object_put(fields.message);
    json_object_put(root);
    free(decode_cause);
    return rc;
}

static int verify_anthropic(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    bool admin = strncmp(key, "sk-ant-admin01", sizeof("sk-ant-admin01") - 1) == 0;
    br_json *type = json_object_new_string(admin ? "Admin Key" : "API Key");
    if (!type) return -1;
    if (json_object_object_add(result->extra_data, "Type", type) != 0) {
        json_object_put(type);
        return -1;
    }
    const br_header headers[] = {
        {"x-api-key", key}, {"Content-Type", "application/json"},
        {"anthropic-version", "2023-06-01"},
    };
    const br_http_request request = {
        .method = "GET",
        .url = admin ? "https://api.anthropic.com/v1/organizations/api_keys" :
                       "https://api.anthropic.com/v1/models",
        .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 933,
    };
    br_http_response response = {0};
    char *error = NULL, *api_cause = NULL;
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 404: break;
        default:
            rc = api_error(&response, &api_cause);
            cause = api_cause;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    if (!rc) rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(api_cause);
    free(error);
    return rc;
}

static int scan_anthropic(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Anthropic scan");
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            rc = fail(error, "out of memory creating Anthropic result");
            break;
        }
        result.extra_data = json_object_new_object();
        if (!result.extra_data ||
            (verify && verify_anthropic(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0) {
            br_result_clear(&result);
            rc = fail(error, "cannot allocate Anthropic result or verification error");
        }
    }
    br_captures_clear(&keys);
    return rc;
}

static const char *const keywords[] = {"sk-ant-api03", "sk-ant-admin01"};
static br_detector anthropic = {
    .type = 933, .version = 0, .name = "Anthropic", .custom_name = "",
    .description = "Anthropic is an AI research company. "
                   "The API keys can be used to access their AI models and services.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_anthropic,
};

int br_anthropic_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Anthropic detector output");
    *out = NULL;
    if (!anthropic.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(sk-ant-(?:admin01|api03)-[\\w\\-]{93}AA)\\b", &regex, error) != 0)
            return -1;
        anthropic.state = regex;
    }
    *out = &anthropic;
    return 0;
}
