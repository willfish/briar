/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/box. */
#include "detectors.h"
#include "key_scan.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *id, *login, *status; char *cause; } user_fields;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int read_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    user_fields *fields = user;
    br_json **slot = NULL;
    const char *field = NULL;
    if (br_json_field_name(name, "id")) { slot = &fields->id; field = "user.id"; }
    else if (br_json_field_name(name, "login")) { slot = &fields->login; field = "user.login"; }
    else if (br_json_field_name(name, "status")) { slot = &fields->status; field = "user.status"; }
    /* Unknown fields are skipped, not converted through a float64 map. Null
     * does not reset a primitive Go struct string, including later duplicates. */
    if (!slot || !value) return 0;
    if (!json_object_is_type(value, json_type_string))
        return br_json_type_cause(value, field, "string", &fields->cause) ? -1 : 1;
    json_object_put(*slot);
    *slot = json_object_get(value);
    return 0;
}

static int put_string(br_json *extra, const char *name, br_json *value)
{
    /* Retain the complete parsed string, including embedded NUL. Missing/null
     * fields still contribute an empty string, never an omitted metadata key. */
    br_json *text = value ? json_object_get(value) : json_object_new_string_len("", 0);
    if (!text) return -1;
    if (json_object_object_add(extra, name, text)) { json_object_put(text); return -1; }
    return 0;
}

static int read_user(const br_http_response *response, br_result *result, char **cause)
{
    user_fields fields = {0}; br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &fields.cause);
    if (!rc && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){response->body.data, end}, read_field, &fields);
        else
            rc = br_json_type_cause(root, NULL, "box.user", &fields.cause) ? -1 : 1;
    }
    if (!rc) {
        br_json *extra = json_object_new_object();
        if (!extra) rc = -1;
        else if (put_string(extra, "user_id", fields.id) || put_string(extra, "username", fields.login) ||
                 put_string(extra, "user_status", fields.status)) {
            json_object_put(extra); rc = -1;
        } else {
            json_object_put(result->extra_data); result->extra_data = extra;
            result->verified = true; /* Root null and an empty object also succeed. */
        }
    }
    json_object_put(root);
    json_object_put(fields.id); json_object_put(fields.login); json_object_put(fields.status);
    *cause = fields.cause;
    /* Decoder/visitor +1 is a candidate decode error. It is not the core
     * setter's positive resource failure. First type errors cannot be repaired
     * by later valid duplicates; no partially assigned metadata is published. */
    return rc < 0 ? -1 : 0;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int verify_box(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    /* Source keys are exactly 32 ASCII alphanumeric bytes. */
    char auth[sizeof("Bearer ") + 32];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", auth}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.box.com/2.0/users/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *json_cause = NULL;
    char status_error[80]; const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            /* Decode one document, not ReadAll: a complete first document can
             * succeed despite later read errors or trailing documents/data. */
            rc = read_user(&response, result, &json_cause); cause = json_cause;
            break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    if (!rc) rc = set_cause(result, cause);
    /* Native streaming/drain/close timing is outside the eager-response ABI. */
    br_http_release(ctx, &response);
    free(json_cause); free(transport_error);
    return rc ? -1 : 0;
}

static int scan_box(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_box, error);
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"box"};
static br_detector box = {
    .type = 1002, .version = 0, .name = "Box", .custom_name = "",
    .description = "Box is a service offering various service for secure collaboration, content management, and workflow. Box token can be used to access and interact with this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_box,
};

int br_box_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Box detector output");
    *out = NULL;
    if (br_key_pattern_init(&box, "\\b([0-9a-zA-Z]{32})\\b", error)) return -1;
    *out = &box;
    return 0;
}
