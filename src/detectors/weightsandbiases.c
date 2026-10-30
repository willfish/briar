/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/weightsandbiases. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char wb_url[] = "https://api.wandb.ai/graphql";
static const char wb_query[] =
    "{\"query\": \"query Viewer { viewer { id username email admin } }\"}";

static int wb_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int wb_put(br_json *object, const char *key, const void *value, size_t len, char **error)
{
    if (len > INT_MAX) return wb_fail(error, "cannot create WeightsAndBiases metadata");
    br_json *text = json_object_new_string_len(value ? value : "", (int)len);
    if (!text || json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return wb_fail(error, "cannot create WeightsAndBiases metadata");
    }
    return 0;
}

static int wb_version(br_result *result, int version, char **error)
{
    if (!result->extra_data && !(result->extra_data = json_object_new_object()))
        return wb_fail(error, "cannot create WeightsAndBiases metadata");
    return wb_put(result->extra_data, "version", version == 1 ? "1" : "2", 1, error);
}

static const char wb_data_type[] =
    "struct { Viewer struct { ID string \"json:\\\"id\\\"\"; Username string \"json:\\\"username\\\"\"; "
    "Email string \"json:\\\"email\\\"\"; Admin bool \"json:\\\"admin\\\"\" } \"json:\\\"viewer\\\"\" }";
static const char wb_viewer_type[] =
    "struct { ID string \"json:\\\"id\\\"\"; Username string \"json:\\\"username\\\"\"; "
    "Email string \"json:\\\"email\\\"\"; Admin bool \"json:\\\"admin\\\"\" }";

typedef struct {
    bool ordinary;
    char *cause;
    char *username;
    size_t username_len;
    char *email;
    size_t email_len;
    bool admin;
} wb_view;

static void wb_view_clear(wb_view *view)
{
    free(view->cause);
    free(view->username);
    free(view->email);
    *view = (wb_view){0};
}

/* First ordinary type error sticks, including a NULL cause. Later helpers still
 * run; their nonzero result is fatal and must not be hidden by that error. */
static int wb_note(wb_view *view, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) {
        free(next);
        return rc;
    }
    if (!view->ordinary) {
        view->ordinary = true;
        view->cause = next;
    } else free(next);
    return 0;
}

static int wb_copy(char **slot, size_t *len, br_json *value)
{
    br_slice text = br_json_text(value);
    char *next = malloc(text.len + 1);
    if (!next) return -1;
    if (text.len) memcpy(next, text.data, text.len);
    next[text.len] = '\0';
    free(*slot);
    *slot = next;
    *len = text.len;
    return 0;
}

static int wb_viewer_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    wb_view *view = user;
    if (br_json_field_name(name, "id")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return wb_note(view, value, ".data.viewer.id", "string");
        return 0; /* Typed, not published. */
    }
    if (br_json_field_name(name, "username")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return wb_note(view, value, ".data.viewer.username", "string");
        return wb_copy(&view->username, &view->username_len, value);
    }
    if (br_json_field_name(name, "email")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return wb_note(view, value, ".data.viewer.email", "string");
        return wb_copy(&view->email, &view->email_len, value);
    }
    if (br_json_field_name(name, "admin")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_boolean))
            return wb_note(view, value, ".data.viewer.admin", "bool");
        view->admin = json_object_get_boolean(value);
    }
    return 0;
}

static int wb_data_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    wb_view *view = user;
    if (!br_json_field_name(name, "viewer")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return wb_note(view, value, ".data.viewer", wb_viewer_type);
    return br_json_each_member(encoded, wb_viewer_member, view);
}

static int wb_root_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    wb_view *view = user;
    if (!br_json_field_name(name, "data")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return wb_note(view, value, "viewerResponse.data", wb_data_type);
    return br_json_each_member(encoded, wb_data_member, view);
}

/* 0 decoded, 1 ordinary cause (possibly NULL), -1 fatal. Decoder is first
 * document. Null leaves a slot unchanged. A decode error stays unverified. */
static int wb_viewer(br_slice body, const char *read_error, bool *verified,
                     br_json **extra, char **cause, char **error)
{
    *verified = false;
    *extra = NULL;
    *cause = NULL;
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_json_first_document(body, read_error, &root, &end, &decode);
    if (rc == 1) {
        json_object_put(root);
        *cause = decode;
        return 1;
    }
    if (rc != 0) {
        json_object_put(root);
        free(decode);
        return wb_fail(error, "cannot decode WeightsAndBiases response");
    }
    free(decode);
    wb_view view = {0};
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object))
            rc = wb_note(&view, root, NULL, "weightsandbiases.viewerResponse");
        else if (body.data && end)
            rc = br_json_each_member((br_slice){body.data, end}, wb_root_member, &view);
    }
    json_object_put(root);
    if (rc != 0) {
        wb_view_clear(&view);
        return wb_fail(error, "cannot decode WeightsAndBiases response");
    }
    if (view.ordinary) {
        *cause = view.cause;
        view.cause = NULL;
        wb_view_clear(&view);
        return 1;
    }
    if (view.username_len > 0) {
        const char *admin = view.admin ? "true" : "false";
        *extra = json_object_new_object();
        if (!*extra || wb_put(*extra, "username", view.username, view.username_len, error) ||
            wb_put(*extra, "email", view.email ? view.email : "", view.email_len, error) ||
            wb_put(*extra, "admin", admin, view.admin ? 4 : 5, error))
            rc = -1;
        else *verified = true;
    }
    if (rc < 0) { json_object_put(*extra); *extra = NULL; }
    wb_view_clear(&view);
    return rc < 0 ? -1 : 0;
}

static int wb_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Constant query is built before NewRequestWithContext. A nil context is
     * that constructor error; Basic auth is reached only after it succeeds. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1) == 0
            ? 0 : wb_fail(error, "cannot set WeightsAndBiases verification error");
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)"api", 3}, key,
                           &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = wb_url, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)wb_query, sizeof(wb_query) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *cause = NULL, status_error[80];
    br_json *extra = NULL;
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error; /* NULL diagnostic stays NULL. */
    } else if (response.status == 200) {
        rc = wb_viewer(response.body, response.body_error, &verified, &extra, &cause, error);
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error),
                 "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    if (rc >= 0) {
        result->verified = verified;
        result->extra_data = extra;
        extra = NULL;
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = wb_fail(error, "cannot set WeightsAndBiases verification error");
        else rc = 0;
    }
    json_object_put(extra);
    br_http_release(ctx, &response);
    free(send_error);
    if (cause != send_error && cause != status_error) free(cause);
    free(authorization);
    return rc;
}

static int wb_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || (detector->version != 1 && detector->version != 2) ||
        !out || (!input.data && input.len))
        return wb_fail(error, "invalid or uninitialized WeightsAndBiases scan");
    size_t original = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* Map insertion keeps one copy. First-seen order stands in for Go's random map. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = wb_fail(&owned, "cannot create WeightsAndBiases result");
        else if (verify && wb_verify(ctx, key, &result, &owned) != 0)
            rc = -1;
        if (rc == 0 && wb_version(&result, detector->version, &owned) != 0) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = wb_fail(&owned, "cannot append WeightsAndBiases result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const v1_keywords[] = {"wandb"};
static br_detector wb_v1 = {
    .type = 1005, .version = 1, .name = "WeightsAndBiases", .custom_name = "",
    .description = "Weights & Biases is a Machine Learning Operations (MLOps) platform that helps track experiments, version datasets, evaluate model performance, and collaborate with team members",
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = wb_scan,
};

static const char *const v2_keywords[] = {"wandb_v1_"};
static br_detector wb_v2 = {
    .type = 1005, .version = 2, .name = "WeightsAndBiases", .custom_name = "",
    .description = "Weights & Biases is a Machine Learning Operations (MLOps) platform that helps track experiments, version datasets, evaluate model performance, and collaborate with team members",
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = wb_scan,
};

static int wb_init(const br_detector **out, br_detector *detector, br_regex **pattern,
                   const char *regex, bool prefixed, char **error)
{
    if (error) *error = NULL;
    if (!out) return wb_fail(error, "invalid WeightsAndBiases detector output");
    *out = NULL;
    if (!*pattern && (prefixed
            ? br_regex_compile_prefixed(detector->keywords, 1, regex, pattern, error)
            : br_regex_compile(regex, pattern, error)) != 0)
        return -1;
    detector->state = *pattern;
    *out = detector;
    return 0;
}

int br_weightsandbiases_v1_init(const br_detector **out, char **error)
{
    static br_regex *pattern;
    return wb_init(out, &wb_v1, &pattern, "\\b([0-9a-f]{40})\\b", true, error);
}

int br_weightsandbiases_v2_init(const br_detector **out, char **error)
{
    static br_regex *pattern;
    return wb_init(out, &wb_v2, &pattern,
                   "\\b(wandb_v1_[A-Za-z0-9]{27}_[A-Za-z0-9]{49})\\b", false, error);
}
