/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/atlassian/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char empty_data_error[] =
    "unsupported upstream panic: Atlassian v1 indexes empty OrgRes.Data";
static const char data_type[] =
    "[]struct { Attributes struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"attributes\\\"\" }";
static const char attributes_type[] = "struct { Name string \"json:\\\"name\\\"\" }";

typedef struct { bool has_first; br_json *first_name; char *cause; } org_response;
typedef struct { org_response *response; bool retain_name; } org_entry;
typedef struct { br_regex *key, *org_id; } atlassian_v2_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Positive means a typed decode cause, negative means allocation failure. */
static int type_error(org_response *response, br_json *value, const char *field, const char *type)
{
    return br_json_type_cause(value, field, type, &response->cause) == 0 ? 1 : -1;
}

static int read_name(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    org_entry *entry = user;
    if (!br_json_field_name(name, "name") || !value) return 0;
    if (!json_object_is_type(value, json_type_string))
        return type_error(entry->response, value, ".data.attributes.name", "string");
    if (entry->retain_name) {
        json_object_put(entry->response->first_name);
        entry->response->first_name = json_object_get(value);
    }
    return 0;
}

static int read_attributes(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    org_entry *entry = user;
    if (!br_json_field_name(name, "attributes") || !value) return 0;
    if (!json_object_is_type(value, json_type_object))
        return type_error(entry->response, value, ".data.attributes", attributes_type);
    return br_json_each_member(encoded_value, read_name, entry);
}

static int read_entry(void *user, size_t index, br_json *value, br_slice encoded_value)
{
    org_response *response = user;
    if (!value) return 0; /* Null into a reused struct is a no-op. */
    if (!json_object_is_type(value, json_type_object))
        return type_error(response, value, "OrgRes.data", data_type + 2);
    org_entry entry = {response, index == 0};
    return br_json_each_member(encoded_value, read_attributes, &entry);
}

static int read_data(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    org_response *response = user;
    if (!br_json_field_name(name, "data")) return 0;
    if (value && !json_object_is_type(value, json_type_array))
        return type_error(response, value, "OrgRes.data", data_type);
    response->has_first = value && json_object_array_length(value) > 0;
    if (!response->has_first) {
        /* Empty arrays replace the backing slice; null sets it to nil. */
        json_object_put(response->first_name);
        response->first_name = NULL;
        return 0;
    }
    /* Nonempty duplicate arrays reuse slot zero. Only its name is observable,
     * but visit and type-check every element, including all nested members. */
    return br_json_each_element(encoded_value, read_entry, response);
}

static int decode_org(br_slice body, const char *body_error, org_response *response)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, body_error, &root, &end, &response->cause);
    if (!rc && root) {
        rc = json_object_is_type(root, json_type_object) ?
            br_json_each_member((br_slice){body.data, end}, read_data, response) :
            type_error(response, root, NULL, "atlassian.OrgRes");
    }
    json_object_put(root);
    return rc;
}

static int put_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int make_result(const br_detector *detector, const char *key, const char *org_id, br_result *result)
{
    if (br_finding_key(result, detector->type, key, "key") != 0) return -1;
    result->extra_data = json_object_new_object();
    if (!result->extra_data ||
        put_text(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/atlassian/") != 0 ||
        put_text(result->extra_data, "version", detector->version == 1 ? "1" : "2") != 0 ||
        (org_id && put_text(result->secret_parts, "organization_id", org_id) != 0)) {
        br_result_clear(result);
        return -1;
    }
    return 0;
}

/* 0: usable candidate; 1: unsupported v1 panic branch; -1: allocation failure. */
static int verify_atlassian(const br_scan_ctx *ctx, const char *key, int32_t version, br_result *result)
{
    size_t len = strlen(key);
    if (len > SIZE_MAX - sizeof("Bearer ")) return -1;
    char *authorization = malloc(len + sizeof("Bearer "));
    if (!authorization) return -1;
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key, len + 1);
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.atlassian.com/admin/v1/orgs",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 190,
    };
    br_http_response response = {0};
    org_response org = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: {
            int decoded = decode_org(response.body, response.body_error, &org);
            if (decoded < 0) rc = -1;
            else if (decoded > 0) cause = org.cause;
            else if (version == 1 && !org.has_first) rc = 1;
            else {
                if (org.has_first) {
                    br_json *name = org.first_name ? json_object_get(org.first_name) : json_object_new_string("");
                    if (!name) rc = -1;
                    else if (json_object_object_add(result->extra_data, "Organization", name) != 0) {
                        json_object_put(name);
                        rc = -1;
                    }
                }
                if (!rc) result->verified = true;
            }
            break;
        }
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    if (!rc) {
        br_slice secret = {result->raw.data, result->raw.len};
        rc = br_result_set_verification_error(result, cause, &secret, 1);
    }
    br_http_release(ctx, &response);
    json_object_put(org.first_name);
    free(org.cause);
    free(error);
    free(authorization);
    return rc;
}

static void discard_additions(br_results *out, size_t original_len)
{
    while (out->len > original_len) br_result_clear(&out->items[--out->len]);
}

static int scan_v1(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Atlassian v1 scan arguments");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, true, error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_result result = {0};
        if (make_result(detector, keys.items[k], NULL, &result) != 0) {
            rc = fail(error, "out of memory creating Atlassian v1 result");
        } else {
            int checked = verify ? verify_atlassian(ctx, keys.items[k], 1, &result) : 0;
            if (checked) rc = fail(error, checked > 0 ? empty_data_error : "out of memory verifying Atlassian v1 result");
            else if (br_results_push(out, &result) != 0) rc = fail(error, "out of memory appending Atlassian v1 result");
        }
        br_result_clear(&result);
    }
    br_captures_clear(&keys);
    if (rc) discard_additions(out, original_len);
    return rc;
}

static int scan_v2(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Atlassian v2 scan arguments");
    const atlassian_v2_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->org_id) return fail(error, "uninitialized Atlassian v2 patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->org_id, input, &ids, true, error);
    /* The absent-ID entry still produces a key-only result. IDs are hints for
     * SecretParts only: they do not change Raw or the verification request. */
    size_t count = ids.len ? ids.len : 1;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < count; ++i) {
            br_result result = {0};
            if (make_result(detector, keys.items[k], ids.len ? ids.items[i] : NULL, &result) != 0 ||
                (verify && verify_atlassian(ctx, keys.items[k], 2, &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Atlassian v2 result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (rc) discard_additions(out, original_len);
    return rc;
}

static const char *const v1_keywords[] = {"atlassian"};
static br_detector v1 = {
    .type = 190, .version = 1, .name = "Atlassian", .custom_name = "",
    .description = "Atlassian provides tools for software development, project management, and content management. "
                   "Atlassian API keys can be used to access and manage these tools and services.",
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_v1,
};
static atlassian_v2_patterns v2_patterns;
static const char *const v2_keywords[] = {"ATCTT3xFfG"};
static const char *const org_prefixes[] = {"org", "id"};
static const br_detector v2 = {
    .type = 190, .version = 2, .name = "Atlassian", .custom_name = "",
    .description = "Atlassian is a software company that provides tools for project management, software development, and collaboration. "
                   "Atlassian tokens can be used to access and manage these tools and services.",
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &v2_patterns, .scan = scan_v2,
};

int br_atlassian_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Atlassian v1 detector output");
    *out = NULL;
    if (!v1.state && br_key_pattern_init(&v1, "\\b([a-zA-Z0-9]{24})\\b", error) != 0) return -1;
    *out = &v1;
    return 0;
}

int br_atlassian_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Atlassian v2 detector output");
    *out = NULL;
    if (!v2_patterns.key && br_regex_compile("\\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\\b", &v2_patterns.key, error) != 0)
        return -1;
    if (!v2_patterns.org_id && br_regex_compile_prefixed(org_prefixes, 2,
            "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", &v2_patterns.org_id, error) != 0)
        return -1;
    *out = &v2;
    return 0;
}
