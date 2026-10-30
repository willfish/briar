/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sonarcloud/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char v1_url[] = "https://sonarcloud.io/api/authentication/validate";
static const char v2_url[] =
    "https://sonarcloud.io/api/projects/search?organization=nonexistent-org-9f2a7c4e1b8d4a6f";
static const char description[] =
    "SonarCloud is a cloud-based code quality and security service. SonarCloud tokens can be used to access project analysis and quality reports.";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int put_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value)) {
        json_object_put(value);
        return -1;
    }
    return 0;
}

static int version_data(br_result *result, int version)
{
    br_json *data = json_object_new_object();
    if (!data) return -1;
    if (put_text(data, "version", version == 1 ? "1" : "2")) {
        json_object_put(data);
        return -1;
    }
    json_object_put(result->extra_data);
    result->extra_data = data;
    return 0;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}


typedef struct {
    bool ordinary;
    bool valid;
    char *cause;
} sonar_fields;

static int note_type(sonar_fields *fields, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) {
        free(next);
        return rc;
    }
    if (!fields->ordinary) {
        fields->ordinary = true;
        fields->cause = next;
    } else free(next);
    return 0;
}

static int note_valid(sonar_fields *fields, br_json *value)
{
    return note_type(fields, value, ".valid", "bool");
}

static int note_valid_root(sonar_fields *fields, br_json *value)
{
    return note_type(fields, value, NULL, "struct { Valid bool \"json:\\\"valid\\\"\" }");
}

static int read_valid(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    sonar_fields *fields = user;
    if (!br_json_field_name(name, "valid")) return 0;
    /* JSON null leaves the bool at its current value. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_boolean)) return note_valid(fields, value);
    fields->valid = json_object_get_boolean(value);
    return 0;
}

/* 0 parsed, 1 ordinary cause (possibly NULL), -1 fatal. Only document +1 is ordinary. */
static int decode_valid(br_slice body, bool *valid, char **cause)
{
    *valid = false;
    *cause = NULL;
    br_json *root = NULL;
    char *decode = NULL;
    int rc = br_json_document(body, &root, &decode);
    if (rc == 1) {
        json_object_put(root);
        *cause = decode;
        return 1;
    }
    if (rc != 0) {
        json_object_put(root);
        free(decode);
        return -1;
    }
    free(decode);
    sonar_fields fields = {0};
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object))
            rc = note_valid_root(&fields, root);
        else if (body.data && body.len)
            rc = br_json_each_member(body, read_valid, &fields);
    }
    json_object_put(root);
    if (rc != 0) {
        free(fields.cause);
        return -1;
    }
    if (fields.ordinary) {
        *cause = fields.cause;
        return 1;
    }
    *valid = fields.valid;
    return 0;
}

static int verify_v1(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* NewRequestWithContext fails before SetBasicAuth. A nil context is not a send. */
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, NULL)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = v1_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    char *owned_cause = NULL;
    int rc = 0;
    bool recorded = false;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        rc = set_cause(result, transport_error);
        recorded = true;
    } else if (response.status != 200) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    } else if (response.body_error) {
        rc = set_cause(result, response.body_error);
        recorded = true;
    } else {
        bool valid = false;
        int decoded = decode_valid(response.body, &valid, &owned_cause);
        if (decoded < 0) rc = -1;
        else if (decoded > 0) {
            rc = set_cause(result, owned_cause);
            recorded = true;
        } else result->verified = valid;
    }
    /* Source always reaches SetVerificationError, including a nil error. */
    if (!rc && !recorded) rc = set_cause(result, cause);
    /* Source defers discard/close and ignores those errors. Release once here. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(owned_cause);
    free(authorization);
    return rc;
}

static int verify_v2(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 64) return -1;
    /* Authorization is added only after a successful constructor. */
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char authorization[72];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 64);
    authorization[71] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = v2_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    bool recorded = false;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        rc = set_cause(result, transport_error);
        recorded = true;
    } else {
        switch (response.status) {
        case 200:
        case 403:
        case 404: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Source always reaches SetVerificationError, including a nil error. */
    if (!rc && !recorded) rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_sonarcloud(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SonarCloud scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* First-seen byte identity is one permitted traversal of the source map. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") ||
            version_data(&result, detector->version))
            rc = fail(&owned_error, "cannot create SonarCloud result");
        else if (verify && (detector->version == 1 ? verify_v1(ctx, key, &result)
                                                   : verify_v2(ctx, key, &result)))
            rc = fail(&owned_error, "cannot verify SonarCloud candidate");
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append SonarCloud result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const v1_keywords[] = {"sonar"};
static const char *const v2_keywords[] = {"sqco_"};
static br_detector sonar_v1 = {
    .type = 767, .version = 1, .name = "SonarCloud", .custom_name = "",
    .description = description, .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_sonarcloud,
};
static br_detector sonar_v2 = {
    .type = 767, .version = 2, .name = "SonarCloud", .custom_name = "",
    .description = description, .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_sonarcloud,
};

int br_sonarcloud_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SonarCloud detector output");
    *out = NULL;
    if (!sonar_v1.state &&
        br_regex_compile_prefixed(v1_keywords, 1, "(?:^|[^@])\\b([0-9a-z]{40})\\b",
                                  (br_regex **)&sonar_v1.state, error))
        return -1;
    *out = &sonar_v1;
    return 0;
}

int br_sonarcloud_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SonarCloud detector output");
    *out = NULL;
    if (!sonar_v2.state &&
        br_regex_compile("\\b(sqco_[0-9A-Za-z]{59})\\b", (br_regex **)&sonar_v2.state, error))
        return -1;
    *out = &sonar_v2;
    return 0;
}
