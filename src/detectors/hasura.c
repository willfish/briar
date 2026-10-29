/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hasura/hasura.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } hasura_patterns;
typedef struct { bool data_nonnil; size_t errors_len; char *cause; } hasura_response;

static int hasura_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void hasura_save(hasura_response *response, char *cause)
{
    if (!response->cause) response->cause = cause;
    else free(cause);
}

static int hasura_type(hasura_response *response, br_json *value,
                       const char *field, const char *expected)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, expected, &cause) != 0 || !cause) {
        free(cause);
        return -1;
    }
    hasura_save(response, cause);
    return 0;
}

static int hasura_numbers(hasura_response *response, br_slice encoded, bool data)
{
    char *cause = NULL;
    int rc = br_json_check_float64_numbers(encoded, &cause);
    if (rc == 1) {
        /* Only this locally generated helper cause is an UnmarshalTypeError.
         * The anonymous source struct contributes .data/.errors, not nested
         * map keys or array indices. Never rewrite arbitrary diagnostics. */
        static const char plain[] = " into Go value of type float64";
        const char *field = data ? " into Go struct field .data of type float64" :
                                   " into Go struct field .errors of type float64";
        size_t len = cause ? strlen(cause) : 0, suffix = strlen(field) + 1;
        if (len < sizeof(plain) - 1 ||
            memcmp(cause + len - (sizeof(plain) - 1), plain, sizeof(plain)) != 0) {
            free(cause);
            return -1;
        }
        size_t prefix = len - (sizeof(plain) - 1);
        if (prefix > SIZE_MAX - suffix) { free(cause); return -1; }
        char *contextual = malloc(prefix + suffix);
        if (!contextual) { free(cause); return -1; }
        memcpy(contextual, cause, prefix);
        memcpy(contextual + prefix, field, suffix);
        free(cause);
        hasura_save(response, contextual);
        return 0; /* Keep visiting after the first ordinary error. */
    }
    free(cause);
    return rc == 0 ? 0 : -1;
}

static int hasura_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    hasura_response *response = user;
    if (br_json_field_name(name, "data")) {
        /* any is replaced, not map-merged; false/0/empty containers are nonnil. */
        response->data_nonnil = value != NULL;
        return hasura_numbers(response, encoded, true);
    }
    if (br_json_field_name(name, "errors")) {
        if (!value) { response->errors_len = 0; return 0; }
        if (!json_object_is_type(value, json_type_array))
            return hasura_type(response, value, ".errors", "[]interface {}");
        response->errors_len = json_object_array_length(value);
        return hasura_numbers(response, encoded, false);
    }
    return 0; /* Unknown struct fields do not convert generic numeric values. */
}

/* Whole-document validation precedes typed visitation. The source's known %w
 * wrapper is structurally unwrapped here, so the setter receives the JSON leaf. */
static int hasura_decode(br_slice body, bool *verified, char **cause, char **error)
{
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc != 0) {
        json_object_put(root);
        if (rc == 1 && *cause) return 0;
        return hasura_fail(error, "cannot decode Hasura JSON");
    }
    hasura_response response = {0};
    if (root && !json_object_is_type(root, json_type_object))
        rc = hasura_type(&response, root, NULL,
            "struct { Data interface {} \"json:\\\"data\\\"\"; Errors []interface {} \"json:\\\"errors\\\"\" }");
    else if (root) rc = br_json_each_member(body, hasura_member, &response);
    json_object_put(root);
    if (rc != 0) {
        free(response.cause);
        return hasura_fail(error, "cannot project Hasura JSON");
    }
    *cause = response.cause;
    *verified = !response.cause && response.data_nonnil && response.errors_len == 0;
    return 0;
}

static int hasura_domain_part(br_json *object, br_slice domain)
{
    if (domain.len > INT_MAX) return -1;
    br_json *text = json_object_new_string_len((const char *)domain.data, (int)domain.len);
    if (!text) return -1;
    if (json_object_object_add(object, "domain", text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static int hasura_finding(br_result *result, int32_t type, br_slice domain, br_slice key)
{
    if (br_finding_key_bytes(result, type, key, "key") != 0) return -1;
    if (key.len == SIZE_MAX || domain.len > SIZE_MAX - key.len - 1) return -1;
    result->raw_v2.len = domain.len + 1 + key.len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, domain.data, domain.len);
    result->raw_v2.data[domain.len] = ':';
    memcpy(result->raw_v2.data + domain.len + 1, key.data, key.len);
    return hasura_domain_part(result->secret_parts, domain);
}

static int hasura_verify(const br_scan_ctx *ctx, br_slice domain, br_slice key,
                         br_result *result, char **error)
{
    static const unsigned char query[] = "{\"query\":\"query { __schema { types { name } } }\"}";
    static const char scheme[] = "https://", path[] = "/v1/graphql";
    size_t overhead = sizeof(scheme) - 1 + sizeof(path);
    if (domain.len > SIZE_MAX - overhead)
        return hasura_fail(error, "Hasura URL is too large");
    char *url = malloc(domain.len + overhead);
    if (!url) return hasura_fail(error, "cannot create Hasura URL");
    memcpy(url, scheme, sizeof(scheme) - 1);
    memcpy(url + sizeof(scheme) - 1, domain.data, domain.len);
    memcpy(url + sizeof(scheme) - 1 + domain.len, path, sizeof(path));
    /* Source constructs the finding, query and complete unbounded URL before
     * NewRequestWithContext can reject a nil context. No hostname validation. */
    if (!ctx) {
        int rc = br_result_set_verification_error(result, "net/http: nil Context", &key, 1);
        free(url);
        return rc == 0 ? 0 : hasura_fail(error, "cannot store Hasura verification error");
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Hasura-Admin-Secret", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = {query, sizeof(query) - 1}, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    br_json *extra = NULL;
    char *send_error = NULL, *owned_cause = NULL;
    const char *cause = NULL;
    char status_error[64];
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else {
        /* ExtraData exists after successful Do, before read/status handling. */
        extra = json_object_new_object();
        if (!extra || hasura_domain_part(extra, domain) != 0)
            rc = hasura_fail(error, "cannot create Hasura extra data");
        else if (response.body_error) {
            owned_cause = strdup(response.body_error);
            if (!owned_cause) rc = hasura_fail(error, "cannot copy Hasura read error");
            else cause = owned_cause;
        } else if (response.status != 200) {
            static const unsigned char unreachable[] = "Project not reachable";
            static const unsigned char unable[] = "Unable to load this project";
            bool unavailable = response.status == 500 &&
                (br_slice_find(response.body, (br_slice){unreachable, sizeof(unreachable) - 1}, 0) != SIZE_MAX ||
                 br_slice_find(response.body, (br_slice){unable, sizeof(unable) - 1}, 0) != SIZE_MAX);
            if (!unavailable) {
                int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
                if (n < 0 || (size_t)n >= sizeof(status_error))
                    rc = hasura_fail(error, "cannot format Hasura status error");
                else cause = status_error;
            }
        } else {
            rc = hasura_decode(response.body, &verified, &owned_cause, error);
            cause = owned_cause;
        }
    }
    /* Exactly one release per send, even failed preparation. Provider-owned
     * request values survive it; shared synthesized headers end at send return.
     * The helper's deferred drain/Close precedes publication and the setter. */
    br_http_release(ctx, &response);
    if (rc == 0) {
        result->verified = verified;
        result->extra_data = extra;
        extra = NULL;
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = hasura_fail(error, "cannot store Hasura verification error");
    }
    json_object_put(extra);
    free(owned_cause);
    free(send_error);
    free(url);
    return rc;
}

static int hasura_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hasura_fail(error, "invalid or uninitialized Hasura scan");
    const hasura_patterns *patterns = detector->state;
    br_captures keys = {0}, domains = {0};
    size_t original_len = out->len;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, true, &owned_error);
    /* Source map iteration is unspecified. Retain first-match order within
     * each unique collection, with the source's key-major domain products. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < domains.len; ++j) {
            br_slice domain = br_captures_at(&domains, j);
            br_result result = {0};
            if (hasura_finding(&result, detector->type, domain, key) != 0)
                rc = hasura_fail(&owned_error, "cannot create Hasura result");
            if (rc == 0 && verify) rc = hasura_verify(ctx, domain, key, &result, &owned_error);
            bool verified = result.verified;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = hasura_fail(&owned_error, "cannot append Hasura result");
            br_result_clear(&result);
            if (rc == 0 && verified) break;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const hasura_keywords[] = {"hasura"};
static hasura_patterns hasura_state;
static br_detector hasura_detector = {
    .type = 1030, .version = 0, .name = "Hasura", .custom_name = "",
    .description = "Hasura is an open-source engine that instantly generates GraphQL and REST APIs over PostgreSQL (and other databases).\n"
                   "\tIt allows you to query, mutate, and subscribe to data in real time. Admin secrets (or admin keys) are used to securely access\n"
                   "\tand manage Hasura projects, giving full control over data, metadata, and schema.",
    .keywords = hasura_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hasura_scan,
};

int br_hasura_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hasura_fail(error, "invalid Hasura detector output");
    *out = NULL;
    if (!hasura_detector.state) {
        if (br_regex_compile_prefixed(hasura_keywords, 1, "\\b([a-zA-Z0-9]{64})\\b", &hasura_state.key, error) != 0)
            return -1;
        if (br_regex_compile("\\b([a-zA-Z0-9-]+\\.hasura\\.app)\\b", &hasura_state.domain, error) != 0) {
            br_regex_free(hasura_state.key);
            hasura_state = (hasura_patterns){0};
            return -1;
        }
        hasura_detector.state = &hasura_state;
    }
    *out = &hasura_detector;
    return 0;
}
