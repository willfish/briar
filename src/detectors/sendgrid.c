/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sendgrid/sendgrid.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sendgrid_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

typedef struct {
    char *data;
    size_t len;
} sendgrid_slot;

typedef struct {
    sendgrid_slot *items;
    size_t len, cap;
    bool failed;
    char *cause;
} sendgrid_fields;

static void sendgrid_keep(sendgrid_fields *fields, char *cause)
{
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = cause;
    } else free(cause);
}

static int sendgrid_note(sendgrid_fields *fields, br_json *value, const char *field,
                         const char *expected)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, expected, &cause) != 0) return -1;
    sendgrid_keep(fields, cause);
    return 0;
}

/* Status is the operation result. type_valid is separate and is false for an ordinary type error. */
__attribute__((weak)) int br_sendgrid_scope_value(br_json *value, bool *type_valid, char **cause)
{
    if (!value || json_object_is_type(value, json_type_null) ||
        json_object_is_type(value, json_type_string)) {
        if (cause) *cause = NULL;
        if (type_valid) *type_valid = true;
        return 0;
    }
    if (type_valid) *type_valid = false;
    return br_json_type_cause(value, "scopesResponse.Scopes", "string", cause);
}

static void sendgrid_slot_clear(sendgrid_slot *slot)
{
    free(slot->data);
    slot->data = NULL;
    slot->len = 0;
}

/* Null and an empty array replace the slice, including its backing array. */
static void sendgrid_discard(sendgrid_fields *fields)
{
    for (size_t i = 0; i < fields->cap; ++i) sendgrid_slot_clear(&fields->items[i]);
    free(fields->items);
    fields->items = NULL;
    fields->len = 0;
    fields->cap = 0;
}

static int sendgrid_grow(sendgrid_fields *fields, size_t n)
{
    if (n <= fields->cap) return 0;
    if (n > SIZE_MAX / sizeof(*fields->items)) return -1;
    sendgrid_slot *items = realloc(fields->items, n * sizeof(*items));
    if (!items) return -1;
    memset(items + fields->cap, 0, (n - fields->cap) * sizeof(*items));
    fields->items = items;
    fields->cap = n;
    return 0;
}

static void sendgrid_clear(sendgrid_fields *fields)
{
    sendgrid_discard(fields);
}

static int sendgrid_store(sendgrid_slot *slot, br_slice text)
{
    if (text.len == SIZE_MAX) return -1;
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len && text.data) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->data);
    slot->data = copy;
    slot->len = text.len;
    return 0;
}

static int sendgrid_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)encoded;
    sendgrid_fields *fields = user;
    sendgrid_slot *slot = &fields->items[index];
    bool type_valid = false;
    char *cause = NULL;
    int op = br_sendgrid_scope_value(value, &type_valid, &cause);
    if (op != 0) {
        free(cause);
        return op;
    }
    if (!type_valid) {
        sendgrid_keep(fields, cause);
        return 0; /* A type error does not replace the existing or fresh slot. */
    }
    free(cause);
    /* Null into a string is ignored, so a reused slot keeps its bytes. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    return sendgrid_store(slot, br_json_text(value));
}

static int sendgrid_scopes(void *user, br_slice name, br_json *value, br_slice encoded)
{
    sendgrid_fields *fields = user;
    if (!br_json_field_name(name, "scopes")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        sendgrid_discard(fields);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array))
        return sendgrid_note(fields, value, "scopesResponse.Scopes", "[]string");
    size_t n = json_object_array_length(value);
    if (!n) {
        sendgrid_discard(fields);
        return 0;
    }
    if (sendgrid_grow(fields, n) != 0) return -1;
    int rc = br_json_each_element(encoded, sendgrid_element, fields);
    if (rc != 0) return rc;
    /* A shorter nonempty array changes live len and keeps allocated slots. */
    fields->len = n;
    return 0;
}

static int sendgrid_extra(const sendgrid_fields *fields, br_result *result)
{
    br_json *extra = json_object_new_object();
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/sendgrid/");
    if (!extra || !guide) {
        json_object_put(extra);
        json_object_put(guide);
        return -1;
    }
    if (json_object_object_add(extra, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        json_object_put(extra);
        return -1;
    }
    if (fields->len) {
        size_t len = fields->len - 1;
        for (size_t i = 0; i < fields->len; ++i) {
            if (fields->items[i].len > SIZE_MAX - len) {
                json_object_put(extra);
                return -1;
            }
            len += fields->items[i].len;
        }
        if (len > INT_MAX) {
            json_object_put(extra);
            return -1;
        }
        char *joined = malloc(len + 1);
        if (!joined) {
            json_object_put(extra);
            return -1;
        }
        size_t at = 0;
        for (size_t i = 0; i < fields->len; ++i) {
            if (i) joined[at++] = ',';
            if (fields->items[i].len && fields->items[i].data)
                memcpy(joined + at, fields->items[i].data, fields->items[i].len);
            at += fields->items[i].len;
        }
        joined[at] = '\0';
        br_json *scopes = json_object_new_string_len(joined, (int)len);
        free(joined);
        if (!scopes || json_object_object_add(extra, "scopes", scopes) != 0) {
            json_object_put(scopes);
            json_object_put(extra);
            return -1;
        }
    }
    result->extra_data = extra;
    result->verified = true;
    return 0;
}

__attribute__((weak)) int br_sendgrid_json_document(br_slice body, const char *read_error,
                                                    br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_sendgrid_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    return br_json_each_member(object, callback, user);
}

static int sendgrid_decode(br_slice body, const char *read_error, br_result *result, char **cause,
                           char **error)
{
    sendgrid_fields fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int parsed = br_sendgrid_json_document(body, read_error, &root, &end, &fields.cause);
    int visit = 0;
    if (parsed == 0 && root && !json_object_is_type(root, json_type_null)) {
        if (json_object_is_type(root, json_type_object))
            visit = br_sendgrid_each_member((br_slice){body.data, end}, sendgrid_scopes, &fields);
        else if (sendgrid_note(&fields, root, NULL, "sendgrid.scopesResponse") != 0) visit = -1;
    }
    if (parsed == 1 || (parsed == 0 && visit == 0 && fields.failed)) {
        *cause = fields.cause;
        json_object_put(root);
        sendgrid_clear(&fields);
        return 0;
    }
    if (parsed != 0 || visit != 0) {
        free(fields.cause);
        json_object_put(root);
        sendgrid_clear(&fields);
        return sendgrid_fail(error, "cannot decode SendGrid response");
    }
    int rc = sendgrid_extra(&fields, result);
    json_object_put(root);
    sendgrid_clear(&fields);
    *cause = fields.cause;
    return rc;
}

static int sendgrid_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (token.len > INT_MAX) return sendgrid_fail(error, "SendGrid token too large");
    char *authorization = malloc(7 + token.len + 1);
    if (!authorization) return sendgrid_fail(error, "cannot allocate SendGrid Authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    int rc = 0;
    const char *cause = NULL;
    char *owned_cause = NULL;
    char status[80];
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        const br_header headers[] = {
            {"Authorization", authorization},
            {"Content-Type", "application/json"},
        };
        const br_http_request request = {
            .method = "GET", .url = "https://api.sendgrid.com/v3/scopes",
            .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error;
            owned_cause = send_error;
        } else if (response.status == 200) {
            rc = sendgrid_decode(response.body, response.body_error, result, &owned_cause, error);
            cause = owned_cause;
        } else if (response.status == 401) {
            /* Definitively invalid. No extra data. */
        } else if (response.status == 403) {
            result->verified = true; /* Valid key, missing scope. Extra stays nil. */
        } else {
            snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
            cause = status;
        }
        br_http_release(ctx, &response);
        if (owned_cause != send_error) free(send_error);
    }
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = sendgrid_fail(error, "cannot store SendGrid verification error");
    free(owned_cause);
    free(authorization);
    return rc;
}

static int sendgrid_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sendgrid_fail(error, "invalid or uninitialized SendGrid scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = sendgrid_fail(&owned_error, "cannot create SendGrid result");
        else if (verify)
            rc = sendgrid_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = sendgrid_fail(&owned_error, "cannot append SendGrid result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sendgrid_keywords[] = {"SG."};
static br_detector sendgrid_detector = {
    .type = 12, .version = 0, .name = "SendGrid", .custom_name = "",
    .description = "SendGrid is a cloud-based service that provides email delivery and marketing campaigns. SendGrid API keys can be used to send emails and manage other email-related tasks.",
    .keywords = sendgrid_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sendgrid_scan,
};

int br_sendgrid_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sendgrid_fail(error, "invalid SendGrid detector output");
    *out = NULL;
    if (!sendgrid_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("(\\bSG\\.[\\w\\-]{20,24}\\.[\\w\\-]{39,50}\\b)", &regex, error) != 0)
            return -1;
        sendgrid_detector.state = regex;
    }
    *out = &sendgrid_detector;
    return 0;
}
