/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/openai/openai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../go_time.h"

#include <json-c/json.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { OPENAI_ABORT = -1, OPENAI_KEEP = 0 } openai_outcome;

typedef struct {
    char *cause;
    bool ordinary; /* Presence is independent of a NULL cause pointer. */
    char *id;
    size_t id_len;
    int64_t created;
    bool mfa;
    size_t norgs;
    char *description;
    size_t description_len;
    bool personal, is_default;
    bool slot_live; /* First orgs.data backing element still exists. */
    bool capture;   /* Element 0 of the current array owns that slot. */
    size_t array_count;
} openai_doc;

static int openai_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* First ordinary error sticks, including a NULL cause. Later helpers still run. */
static int openai_note(openai_doc *doc, char *cause)
{
    if (doc->ordinary) {
        free(cause);
        return 0;
    }
    doc->ordinary = true;
    doc->cause = cause;
    return 0;
}

static int openai_type(openai_doc *doc, br_json *value, const char *field, const char *expected)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, expected, &cause) != 0) {
        free(cause);
        return -1;
    }
    return openai_note(doc, cause);
}

static int openai_copy(char **dest, size_t *dest_len, br_json *value)
{
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data ? text.data : (const unsigned char *)"", text.len);
    copy[text.len] = '\0';
    free(*dest);
    *dest = copy;
    if (dest_len) *dest_len = text.len;
    return 0;
}

/* interface{} conversion. Unknown struct fields are not passed here. */
static int openai_float64(openai_doc *doc, br_slice encoded, const char *field)
{
    char *cause = NULL;
    int rc = br_json_check_float64_numbers(encoded, &cause);
    if (rc == 0) return 0;
    if (rc != 1) {
        free(cause);
        return -1;
    }
    if (!cause) return openai_note(doc, NULL);
    static const char suffix[] = " into Go value of type float64";
    size_t n = strlen(cause), suffix_len = sizeof(suffix) - 1;
    if (n < suffix_len || memcmp(cause + n - suffix_len, suffix, suffix_len) != 0)
        return openai_note(doc, cause);
    const char middle[] = " into Go struct field ";
    const char end[] = " of type float64";
    size_t prefix = n - suffix_len, field_len = strlen(field);
    if (prefix > SIZE_MAX - (sizeof(middle) - 1) - field_len - sizeof(end)) {
        free(cause);
        return -1;
    }
    char *message = malloc(prefix + sizeof(middle) - 1 + field_len + sizeof(end));
    if (!message) {
        free(cause);
        return -1;
    }
    memcpy(message, cause, prefix);
    memcpy(message + prefix, middle, sizeof(middle) - 1);
    memcpy(message + prefix + sizeof(middle) - 1, field, field_len);
    memcpy(message + prefix + sizeof(middle) - 1 + field_len, end, sizeof(end));
    free(cause);
    return openai_note(doc, message);
}

static int openai_int_cause(openai_doc *doc, br_slice token, const char *field)
{
    const char prefix[] = "json: cannot unmarshal number ";
    const char middle[] = " into Go struct field ";
    const char suffix[] = " of type int";
    if (token.len > SIZE_MAX - sizeof(prefix) - sizeof(middle) - sizeof(suffix)) return -1;
    char *message = malloc(sizeof(prefix) - 1 + token.len + sizeof(middle) - 1 + strlen(field) + sizeof(suffix));
    if (!message) return -1;
    char *at = message;
    memcpy(at, prefix, sizeof(prefix) - 1);
    at += sizeof(prefix) - 1;
    if (token.len) memcpy(at, token.data, token.len);
    at += token.len;
    memcpy(at, middle, sizeof(middle) - 1);
    at += sizeof(middle) - 1;
    memcpy(at, field, strlen(field));
    at += strlen(field);
    memcpy(at, suffix, sizeof(suffix));
    doc->ordinary = true;
    doc->cause = message;
    return 0;
}

static int openai_int(openai_doc *doc, br_slice encoded, const char *field, int64_t *out)
{
    size_t begin = 0;
    while (begin < encoded.len && (encoded.data[begin] == ' ' || encoded.data[begin] == '\t' ||
                                   encoded.data[begin] == '\n' || encoded.data[begin] == '\r'))
        ++begin;
    br_slice token = {encoded.data + begin, encoded.len - begin};
    bool integer = token.len && (token.data[0] == '-' || (token.data[0] >= '0' && token.data[0] <= '9'));
    for (size_t i = token.data && token.data[0] == '-' ? 1 : 0; integer && i < token.len; ++i)
        integer = token.data[i] >= '0' && token.data[i] <= '9';
    if (!integer) return doc->ordinary ? 0 : openai_int_cause(doc, token, field);
    char *text = malloc(token.len + 1);
    if (!text) return -1;
    memcpy(text, token.data, token.len);
    text[token.len] = '\0';
    errno = 0;
    char *end = NULL;
    long long value = strtoll(text, &end, 10);
    bool bad = errno == ERANGE || end != text + token.len;
    free(text);
    if (bad) return doc->ordinary ? 0 : openai_int_cause(doc, token, field);
    if (out) *out = (int64_t)value;
    return 0;
}

static int openai_string_field(openai_doc *doc, br_json *value, const char *field, char **dest,
                                 size_t *dest_len)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) return openai_type(doc, value, field, "string");
    return dest ? openai_copy(dest, dest_len, value) : 0;
}

static int openai_bool_field(openai_doc *doc, br_json *value, const char *field, bool *dest)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_boolean)) return openai_type(doc, value, field, "bool");
    if (dest) *dest = json_object_get_boolean(value);
    return 0;
}

static int openai_named(br_slice name, const char *expected)
{
    return br_json_field_name(name, expected);
}

static int openai_settings_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    (void)encoded;
    if (openai_named(name, "threads_ui_visibility"))
        return openai_string_field(doc, value, "settings.orgs.data.settings.threads_ui_visibility", NULL, NULL);
    if (openai_named(name, "usage_dashboard_visibility"))
        return openai_string_field(doc, value, "settings.orgs.data.settings.usage_dashboard_visibility", NULL, NULL);
    return 0;
}

static int openai_projects_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    if (openai_named(name, "object"))
        return openai_string_field(doc, value, "projects.orgs.data.projects.object", NULL, NULL);
    if (openai_named(name, "data")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_array))
            return openai_type(doc, value, "projects.orgs.data.projects.data", "[]interface {}");
        return openai_float64(doc, encoded, "projects.orgs.data.projects.data");
    }
    return 0;
}

static int openai_data_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    bool slot = doc->capture;
    if (openai_named(name, "object"))
        return openai_string_field(doc, value, "data.orgs.data.object", NULL, NULL);
    if (openai_named(name, "id"))
        return openai_string_field(doc, value, "data.orgs.data.id", NULL, NULL);
    if (openai_named(name, "created")) {
        int64_t ignored = 0;
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
            return openai_type(doc, value, "data.orgs.data.created", "int");
        return openai_int(doc, encoded, "data.orgs.data.created", &ignored);
    }
    if (openai_named(name, "title"))
        return openai_string_field(doc, value, "data.orgs.data.title", NULL, NULL);
    if (openai_named(name, "name"))
        return openai_string_field(doc, value, "data.orgs.data.name", NULL, NULL);
    if (openai_named(name, "description"))
        return openai_string_field(doc, value, "data.orgs.data.description",
                                    slot ? &doc->description : NULL, slot ? &doc->description_len : NULL);
    if (openai_named(name, "personal"))
        return openai_bool_field(doc, value, "data.orgs.data.personal", slot ? &doc->personal : NULL);
    if (openai_named(name, "is_default"))
        return openai_bool_field(doc, value, "data.orgs.data.is_default", slot ? &doc->is_default : NULL);
    if (openai_named(name, "role"))
        return openai_string_field(doc, value, "data.orgs.data.role", NULL, NULL);
    if (openai_named(name, "parent_org_id"))
        return openai_float64(doc, encoded, "data.orgs.data.parent_org_id");
    if (openai_named(name, "settings")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_object))
            return openai_type(doc, value, "data.orgs.data.settings", "openai.settings");
        return br_json_each_member(encoded, openai_settings_member, doc);
    }
    if (openai_named(name, "projects")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_object))
            return openai_type(doc, value, "data.orgs.data.projects", "openai.projects");
        return br_json_each_member(encoded, openai_projects_member, doc);
    }
    return 0;
}

static void openai_reset_slot(openai_doc *doc)
{
    free(doc->description);
    doc->description = NULL;
    doc->description_len = 0;
    doc->personal = false;
    doc->is_default = false;
    doc->slot_live = false;
    doc->norgs = 0;
}

static int openai_data_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    doc->array_count = index + 1;
    doc->capture = index == 0;
    /* A new backing element is zero. Null into an existing struct is ignored. */
    if (index == 0 && !doc->slot_live) {
        free(doc->description);
        doc->description = NULL;
        doc->description_len = 0;
        doc->personal = false;
        doc->is_default = false;
    }
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return openai_type(doc, value, "orgs.orgs.data", "openai.data");
    return br_json_each_member(encoded, openai_data_member, doc);
}

static int openai_orgs_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    if (openai_named(name, "object"))
        return openai_string_field(doc, value, "orgs.orgs.object", NULL, NULL);
    if (openai_named(name, "data")) {
        /* null and [] replace the slice. A later array reuses only a live slot. */
        if (!value || json_object_is_type(value, json_type_null)) {
            openai_reset_slot(doc);
            return 0;
        }
        if (!json_object_is_type(value, json_type_array))
            return openai_type(doc, value, "orgs.orgs.data", "[]openai.data");
        doc->array_count = 0;
        doc->capture = false;
        int rc = br_json_each_element(encoded, openai_data_element, doc);
        if (rc != 0) return rc;
        if (doc->array_count == 0) {
            openai_reset_slot(doc);
            return 0;
        }
        doc->norgs = doc->array_count;
        doc->slot_live = true;
        return 0;
    }
    return 0;
}

static int openai_root_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    openai_doc *doc = user;
    if (openai_named(name, "object"))
        return openai_string_field(doc, value, "response.object", NULL, NULL);
    if (openai_named(name, "id"))
        return openai_string_field(doc, value, "response.id", &doc->id, &doc->id_len);
    if (openai_named(name, "email"))
        return openai_float64(doc, encoded, "response.email");
    if (openai_named(name, "name"))
        return openai_float64(doc, encoded, "response.name");
    if (openai_named(name, "picture"))
        return openai_float64(doc, encoded, "response.picture");
    if (openai_named(name, "phone_number"))
        return openai_float64(doc, encoded, "response.phone_number");
    if (openai_named(name, "created")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
            return openai_type(doc, value, "response.created", "int");
        return openai_int(doc, encoded, "response.created", &doc->created);
    }
    if (openai_named(name, "mfa_flag_enabled"))
        return openai_bool_field(doc, value, "response.mfa_flag_enabled", &doc->mfa);
    if (openai_named(name, "has_projects_archive"))
        return openai_bool_field(doc, value, "response.has_projects_archive", NULL);
    if (openai_named(name, "has_payg_project_spend_limit"))
        return openai_bool_field(doc, value, "response.has_payg_project_spend_limit", NULL);
    if (openai_named(name, "amr")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_array))
            return openai_type(doc, value, "response.amr", "[]interface {}");
        return openai_float64(doc, encoded, "response.amr");
    }
    if (openai_named(name, "orgs")) {
        /* null into the struct value is ignored and does not reset it. */
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_object))
            return openai_type(doc, value, "response.orgs", "openai.orgs");
        return br_json_each_member(encoded, openai_orgs_member, doc);
    }
    return 0;
}

static void openai_doc_clear(openai_doc *doc)
{
    free(doc->cause);
    free(doc->id);
    free(doc->description);
    memset(doc, 0, sizeof(*doc));
}

static int openai_decode(br_slice body, const char *read_error, openai_doc *doc, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int decoded = br_json_first_document(body, read_error, &root, &end, &cause);
    /* Only exact document status +1 is ordinary. Null success is 0. */
    if (decoded == 1) {
        doc->ordinary = true;
        doc->cause = cause;
        json_object_put(root);
        return 1;
    }
    if (decoded != 0) {
        free(cause);
        json_object_put(root);
        return openai_fail(error, "cannot decode OpenAI response");
    }
    free(cause);
    int rc = 0;
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            char *typed = NULL;
            if (br_json_type_cause(root, NULL, "openai.response", &typed) != 0) {
                free(typed);
                rc = -1;
            } else if (openai_note(doc, typed) != 0) rc = -1;
        } else {
            int visit = br_json_each_member((br_slice){body.data, end}, openai_root_member, doc);
            if (visit != 0) rc = -1;
        }
    }
    json_object_put(root);
    if (rc != 0) return openai_fail(error, "cannot project OpenAI response");
    return doc->ordinary ? 1 : 0;
}

static int openai_add_len(br_json *object, const char *key, const void *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *text = json_object_new_string_len(value ? value : "", (int)len);
    if (!text || json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static int openai_add(br_json *object, const char *key, const char *value)
{
    return openai_add_len(object, key, value, value ? strlen(value) : 0);
}

static bool openai_digits(const unsigned char *s, size_t n, size_t at, size_t count)
{
    if (at + count > n) return false;
    for (size_t i = 0; i < count; ++i)
        if (s[at + i] < '0' || s[at + i] > '9') return false;
    return true;
}

/* Project time.Unix(sec, 0).Format(RFC3339) from Go's Time.String() bytes. */
static int openai_created_at(int64_t unix_seconds, char **out, size_t *out_len, char **error)
{
    br_bytes formatted = {0};
    if (br_go_time_unix_string(unix_seconds, &formatted, error) != 0) return -1;
    const unsigned char *s = formatted.data;
    size_t n = formatted.len, i = 0, year_digits = 0;
    if (i < n && s[i] == '-') ++i;
    while (i < n && s[i] >= '0' && s[i] <= '9') { ++i; ++year_digits; }
    bool shape = year_digits && i + 21 <= n && s[i] == '-' && openai_digits(s, n, i + 1, 2) &&
                 s[i + 3] == '-' && openai_digits(s, n, i + 4, 2) && s[i + 6] == ' ' &&
                 openai_digits(s, n, i + 7, 2) && s[i + 9] == ':' && openai_digits(s, n, i + 10, 2) &&
                 s[i + 12] == ':' && openai_digits(s, n, i + 13, 2) && s[i + 15] == ' ' &&
                 (s[i + 16] == '+' || s[i + 16] == '-') && openai_digits(s, n, i + 17, 4);
    if (!shape) {
        free(formatted.data);
        return openai_fail(error, "cannot format OpenAI metadata");
    }
    bool zulu = s[i + 16] == '+' && !memcmp(s + i + 17, "0000", 4);
    size_t date_len = i + 6;
    size_t need = date_len + 1 + 8 + (zulu ? 1 : 6);
    char *text = malloc(need + 1);
    if (!text) {
        free(formatted.data);
        return openai_fail(error, "cannot format OpenAI metadata");
    }
    memcpy(text, s, date_len);
    text[date_len] = 'T';
    memcpy(text + date_len + 1, s + i + 7, 8);
    size_t at = date_len + 9;
    if (zulu) text[at++] = 'Z';
    else {
        text[at++] = (char)s[i + 16];
        text[at++] = (char)s[i + 17];
        text[at++] = (char)s[i + 18];
        text[at++] = ':';
        text[at++] = (char)s[i + 19];
        text[at++] = (char)s[i + 20];
    }
    text[at] = '\0';
    free(formatted.data);
    *out = text;
    *out_len = at;
    return 0;
}

static int openai_metadata(br_result *result, const openai_doc *doc, char **error)
{
    char total[32];
    char *created = NULL;
    size_t created_len = 0;
    int n = snprintf(total, sizeof(total), "%zu", doc->norgs);
    if (n < 0 || (size_t)n >= sizeof(total) ||
        openai_created_at(doc->created, &created, &created_len, error) != 0)
        return error && *error ? -1 : openai_fail(error, "cannot format OpenAI metadata");
    result->extra_data = json_object_new_object();
    int rc = !result->extra_data ||
             openai_add_len(result->extra_data, "id", doc->id, doc->id ? doc->id_len : 0) != 0 ||
             openai_add(result->extra_data, "total_orgs", total) != 0 ||
             openai_add(result->extra_data, "mfa_enabled", doc->mfa ? "true" : "false") != 0 ||
             openai_add_len(result->extra_data, "created_at", created, created_len) != 0;
    free(created);
    if (rc) return openai_fail(error, "cannot create OpenAI metadata");
    if (doc->norgs > 0 &&
        (openai_add_len(result->extra_data, "description", doc->description,
                        doc->description ? doc->description_len : 0) != 0 ||
         openai_add(result->extra_data, "is_personal", doc->personal ? "true" : "false") != 0 ||
         openai_add(result->extra_data, "is_default", doc->is_default ? "true" : "false") != 0))
        return openai_fail(error, "cannot create OpenAI organization metadata");
    return 0;
}

static int openai_cause(br_result *result, const char *cause, char **error)
{
    /* SetVerificationError is called with no secrets. */
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return openai_fail(error, "cannot set OpenAI verification error");
    return 0;
}

static bool openai_retry_status(int status)
{
    return status == 0 || status == 429 || (status >= 500 && status != 501);
}

static bool openai_retry_error(bool failed, const char *cause)
{
    if (!failed) return false;
    /* Missing text is still a known error, not context cancellation. */
    if (!cause) return true;
    return strcmp(cause, "context canceled") != 0 &&
           strcmp(cause, "context deadline exceeded") != 0;
}

static openai_outcome openai_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Nil context fails in NewRequestWithContext, before Header.Set, and is kept. */
    if (!ctx) {
        if (openai_cause(result, "net/http: nil Context", error) != 0) return OPENAI_ABORT;
        return OPENAI_KEEP;
    }
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) {
        openai_fail(error, "cannot format OpenAI authorization");
        return OPENAI_ABORT;
    }
    memcpy(authorization, "Bearer ", 7);
    if (key.len) memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json; charset=utf-8"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.openai.com/v1/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    /* RetryableHTTPClient timeout 10s, RetryMax 2: one attempt plus two retries.
     * Connection errors, status 0, 429 and 5xx except 501 are retried. Wait and
     * jitter are not slept here; this tree has no retry client to host them. */
    br_http_response response = {0};
    char *transport_error = NULL;
    bool sent = false, send_failed = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (sent) br_http_release(ctx, &response);
        free(transport_error);
        transport_error = NULL;
        int send_rc = br_http_send(ctx, &request, &response, &transport_error);
        sent = true;
        send_failed = send_rc != 0;
        if (send_failed) {
            if (attempt == 2 || !openai_retry_error(true, transport_error)) break;
            continue;
        }
        if (attempt == 2 || !openai_retry_status(response.status)) break;
    }
    const char *cause = NULL;
    char status_error[80];
    openai_doc doc = {0};
    int rc = 0;
    if (send_failed)
        cause = transport_error;
    else if (response.status == 200) {
        int decoded = openai_decode(response.body, response.body_error, &doc, error);
        if (decoded < 0) rc = -1;
        else if (decoded == 1) cause = doc.cause;
        else if (decoded != 0) rc = -1;
        else {
            result->verified = true;
            rc = openai_metadata(result, &doc, error);
        }
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = openai_fail(error, "cannot format OpenAI status");
        else cause = status_error;
    }
    if (rc == 0) rc = openai_cause(result, cause, error);
    if (sent) br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    openai_doc_clear(&doc);
    return rc == 0 ? OPENAI_KEEP : OPENAI_ABORT;
}

static int openai_redact(br_result *result, br_slice token, char **error)
{
    size_t suffix_at = token.len - 1 < 47 ? token.len - 1 : 47;
    size_t suffix_len = token.len - suffix_at;
    char *redacted = malloc(6 + suffix_len + 1);
    if (!redacted) return openai_fail(error, "cannot redact OpenAI token");
    memcpy(redacted, token.data, 3);
    memcpy(redacted + 3, "...", 3);
    if (suffix_len) memcpy(redacted + 6, token.data + suffix_at, suffix_len);
    redacted[6 + suffix_len] = '\0';
    result->redacted = redacted;
    return 0;
}

static int openai_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return openai_fail(error, "invalid or uninitialized OpenAI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Go stores a map, so duplicates collapse. Iteration order is unspecified;
     * first-seen order is the stable choice. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        openai_outcome outcome = OPENAI_KEEP;
        if (key.len < 3 || br_finding_key_bytes(&result, detector->type, key, "key") != 0 ||
            openai_redact(&result, key, &owned_error) != 0) {
            if (!owned_error) openai_fail(&owned_error, "cannot create OpenAI result");
            outcome = OPENAI_ABORT;
        } else if (verify)
            outcome = openai_verify(ctx, key, &result, &owned_error);
        if (outcome == OPENAI_ABORT) rc = -1;
        else if (br_results_push(out, &result) != 0) {
            openai_fail(&owned_error, "cannot append OpenAI result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const openai_keywords[] = {"T3BlbkFJ"};
static br_regex *openai_regex;
static br_detector openai_detector = {
    .type = 201, .version = 0, .name = "OpenAI", .custom_name = "",
    .description = "OpenAI provides various AI models and services. "
                   "The API keys can be used to access and interact with these models and services.",
    .keywords = openai_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = openai_scan,
};

int br_openai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return openai_fail(error, "invalid OpenAI detector output");
    *out = NULL;
    if (!openai_regex && br_regex_compile(
            "\\b(sk-(?:(?:proj|svcacct|service)-[A-Za-z0-9_-]+|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+)\\b",
            &openai_regex, error) != 0)
        return -1;
    openai_detector.state = openai_regex;
    *out = &openai_detector;
    return 0;
}
