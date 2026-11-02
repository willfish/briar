/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/railwayapp/railwayapp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "json.h"
#include <json-c/json.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const railway_keywords[] = {"railway"};
static const char railway_url[] = "https://backboard.railway.app/graphql/v2";
static const char railway_body[] = "{\"query\":\"query me {me {email}}\"}";
static const char railway_guide[] = "https://howtorotate.com/docs/tutorials/railwayapp/";

static int railway_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int railway_store(br_result *result, const char *cause, char **error)
{
    /* SetVerificationError is called with no secrets. */
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return railway_fail(error, "cannot set RailwayApp verification error");
    return 0;
}

static bool railway_header(const br_http_response *response)
{
    for (size_t i = 0; i < response->nheaders; ++i) {
        const char *name = response->headers[i].name, *value = response->headers[i].value;
        if (!name || !value) continue;
        const char *want = "x-ratelimit-remaining";
        size_t n = 0;
        for (; name[n] && want[n]; ++n) {
            unsigned char c = (unsigned char)name[n];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            if (c != (unsigned char)want[n]) break;
        }
        if (!name[n] && !want[n]) return !strcmp(value, "0");
    }
    return false;
}

typedef struct { size_t errors; bool saw_errors; char *cause; bool ordinary; } railway_parsed;

static int railway_note(railway_parsed *parsed, char *next)
{
    if (parsed->ordinary) { free(next); return 0; }
    parsed->ordinary = true;
    parsed->cause = next;
    return 0;
}

static int railway_float(railway_parsed *parsed, br_slice encoded, const char *field)
{
    char *raw = NULL;
    int rc = br_json_check_float64_numbers(encoded, &raw);
    if (rc == 0) { free(raw); return 0; }
    if (rc != 1) { free(raw); return -1; }
    /* Helper +1 is ordinary even when it owns no text. Never strlen a NULL cause. */
    if (!raw) return railway_note(parsed, NULL);
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go value of type float64";
    size_t raw_len = strlen(raw), prefix_len = sizeof(prefix) - 1, suffix_len = sizeof(suffix) - 1;
    if (raw_len < prefix_len + suffix_len || memcmp(raw, prefix, prefix_len) != 0 ||
        memcmp(raw + raw_len - suffix_len, suffix, suffix_len) != 0)
        return railway_note(parsed, raw);
    size_t token_len = raw_len - prefix_len - suffix_len;
    if (token_len > INT_MAX) { free(raw); return -1; }
    size_t field_len = strlen(field);
    size_t fixed = sizeof("json: cannot unmarshal number  into Go struct field  of type float64");
    if (token_len > SIZE_MAX - fixed || field_len > SIZE_MAX - fixed - token_len) { free(raw); return -1; }
    size_t size = fixed + token_len + field_len;
    char *message = malloc(size);
    if (!message) { free(raw); return -1; }
    int n = snprintf(message, size, "json: cannot unmarshal number %.*s into Go struct field %s of type float64",
                     (int)token_len, raw + prefix_len, field);
    free(raw);
    if (n < 0 || (size_t)n >= size) { free(message); return -1; }
    return railway_note(parsed, message);
}

static int railway_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    railway_parsed *parsed = user;
    if (br_json_field_name(name, "data")) return railway_float(parsed, encoded, "graphQLResponse.data");
    if (!br_json_field_name(name, "errors")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        parsed->saw_errors = true;
        parsed->errors = 0;
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) {
        char *typed = NULL;
        if (br_json_type_cause(value, "graphQLResponse.errors", "[]interface {}", &typed) != 0) {
            free(typed);
            return -1;
        }
        return railway_note(parsed, typed);
    }
    int rc = railway_float(parsed, encoded, "graphQLResponse.errors");
    if (rc) return rc;
    parsed->saw_errors = true;
    parsed->errors = (size_t)json_object_array_length(value);
    return 0;
}

static int railway_decode(br_slice body, bool *verified, char **cause)
{
    *verified = false;
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc < 0 || rc > 1) { json_object_put(root); free(*cause); *cause = NULL; return -1; }
    if (rc == 1) { json_object_put(root); return 1; }
    if (json_object_is_type(root, json_type_null)) { json_object_put(root); *verified = true; return 0; }
    if (!json_object_is_type(root, json_type_object)) {
        char *typed = NULL;
        int typed_rc = br_json_type_cause(root, NULL, "railwayapp.graphQLResponse", &typed);
        json_object_put(root);
        if (typed_rc != 0) { free(typed); return -1; }
        *cause = typed;
        return 1;
    }
    json_object_put(root);
    railway_parsed parsed = {0};
    rc = br_json_each_member(body, railway_member, &parsed);
    /* A visitor result is never reclassified as an ordinary decode error. */
    if (rc != 0) { free(parsed.cause); return -1; }
    if (parsed.ordinary) { *cause = parsed.cause; return 1; }
    *verified = parsed.errors == 0;
    return 0;
}

static int railway_verify_key(const br_scan_ctx *ctx, const char *key, size_t key_len,
                              br_result *result, char **error)
{
    /* Payload exists before NewRequestWithContext. Headers follow a successful constructor. */
    if (!ctx) return railway_store(result, "net/http: nil Context", error);
    if (key_len > SIZE_MAX - 8) return railway_fail(error, "RailwayApp authorization is too large");
    char *authorization = malloc(8 + key_len);
    if (!authorization) return railway_fail(error, "cannot format RailwayApp authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, key_len);
    authorization[7 + key_len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = railway_url, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)railway_body, sizeof(railway_body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    char *cause = NULL;
    int rc = 0;
    bool verified = false;
    if (send_rc != 0) {
        if (transport_error && !(cause = strdup(transport_error)))
            rc = railway_fail(error, "cannot copy RailwayApp transport error");
    }
    else if (response.status != 200) {
        char status_error[80];
        int n = snprintf(status_error, sizeof(status_error),
                         "railway app verification failed with status code %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = railway_fail(error, "cannot format RailwayApp status");
        else cause = strdup(status_error);
    } else if (!railway_header(&response)) {
        if (response.body_error) cause = strdup(response.body_error);
        else {
            int decoded = railway_decode(response.body, &verified, &cause);
            if (decoded < 0 || decoded > 1) rc = railway_fail(error, "cannot decode RailwayApp response");
            else if (decoded == 0 && !cause) result->verified = verified;
        }
    }
    if (!rc) rc = railway_store(result, cause, error);
    free(cause);
    free(transport_error);
    free(authorization);
    br_http_release(ctx, &response);
    return rc;
}

static int railway_metadata(br_result *result, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string(railway_guide);
    if (!result->extra_data || !guide ||
        json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return railway_fail(error, "cannot create RailwayApp metadata");
    }
    return 0;
}

static int railway_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return railway_fail(error, "invalid or uninitialized RailwayApp scan");
    size_t original_len = out->len;
    br_captures found = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < found.len; ++i)
        if (br_captures_push(&keys, br_captures_at(&found, i), true, &owned_error) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 36)
            rc = railway_fail(&owned_error, "invalid RailwayApp capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = railway_fail(&owned_error, "cannot create RailwayApp result");
        else if (railway_metadata(&result, &owned_error) != 0)
            rc = -1;
        else if (verify)
            rc = railway_verify_key(ctx, keys.items[i], key.len, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = railway_fail(&owned_error, "cannot append RailwayApp result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&found);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector railway_detector = {
    .type = 999, .version = 0, .name = "RailwayApp", .custom_name = "",
    .description = "Railway is a deployment platform designed to streamline the software development life-cycle, starting with instant deployments and effortless scale, extending to CI/CD integrations and built-in observability.",
    .keywords = railway_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = railway_scan,
};

int br_railwayapp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return railway_fail(error, "invalid RailwayApp detector output");
    *out = NULL;
    if (br_key_pattern_init(&railway_detector,
                            "\\b([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\\b", error) != 0)
        return -1;
    *out = &railway_detector;
    return 0;
}
