/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared response-document mechanics extracted from the Algolia detector. */
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool json_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int decode_cause(char **cause, const char *message)
{
    *cause = strdup(message);
    return *cause ? 1 : -1;
}

static int syntax_cause(enum json_tokener_error code, br_slice body, size_t offset, char **cause)
{
    unsigned char c = offset < body.len ? body.data[offset] : 0;
    char byte[16], message[192];
    if (c == '\n') strcpy(byte, "'\\n'");
    else if (c == '\r') strcpy(byte, "'\\r'");
    else if (c == '\t') strcpy(byte, "'\\t'");
    else if (c == '\\') strcpy(byte, "'\\\\'");
    else if (c == '\'') strcpy(byte, "'\\\''");
    else if (c < 32 || c >= 127) snprintf(byte, sizeof(byte), "'\\x%02x'", c);
    else snprintf(byte, sizeof(byte), "'%c'", c);
    const char *context;
    switch (code) {
    case json_tokener_error_parse_object_key_name: context = "looking for beginning of object key string"; break;
    case json_tokener_error_parse_object_key_sep: context = "after object key"; break;
    case json_tokener_error_parse_object_value_sep: context = "after object key:value pair"; break;
    case json_tokener_error_parse_array: context = "after array element"; break;
    default: context = "looking for beginning of value"; break;
    }
    snprintf(message, sizeof(message), "invalid character %s %s", byte, context);
    return decode_cause(cause, message);
}

int br_json_first_document(br_slice body, const char *read_error, br_json **out,
                            size_t *end, char **cause)
{
    *out = NULL;
    *end = 0;
    *cause = NULL;
    if (body.len > INT_MAX) return -1;
    struct json_tokener *tokener = json_tokener_new_ex(10001);
    if (!tokener) return -1;
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT | JSON_TOKENER_ALLOW_TRAILING_CHARS);
    br_json *value = json_tokener_parse_ex(tokener, body.data ? (const char *)body.data : "", (int)body.len);
    enum json_tokener_error code = json_tokener_get_error(tokener);
    size_t offset = json_tokener_get_parse_end(tokener);
    bool incomplete = code == json_tokener_continue;
    if (incomplete && !read_error) {
        value = json_tokener_parse_ex(tokener, " ", 1);
        code = json_tokener_get_error(tokener);
    }
    if (code != json_tokener_success) {
        int rc;
        if (incomplete) {
            bool empty = true;
            for (size_t i = 0; i < body.len; ++i)
                if (!json_space(body.data[i])) { empty = false; break; }
            rc = decode_cause(cause, read_error ? read_error : empty ? "EOF" : "unexpected EOF");
        } else rc = syntax_cause(code, body, offset, cause);
        json_object_put(value);
        json_tokener_free(tokener);
        return rc;
    }
    *out = value;
    *end = incomplete ? body.len : offset;
    json_tokener_free(tokener);
    /* json-c accepts these non-JSON constants even with strict parsing enabled. */
    bool string = false, escape = false;
    for (size_t i = 0; i < *end; ++i) {
        unsigned char c = body.data[i];
        if (string) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') string = false;
        } else if (c == '"') string = true;
        else if (c == 'N' || c == 'I' || c == 'i') {
            json_object_put(*out);
            *out = NULL;
            return syntax_cause(json_tokener_error_parse_unexpected, body, i, cause);
        }
    }
    return 0;
}

static const char *type_word(br_json *value)
{
    switch (json_object_get_type(value)) {
    case json_type_boolean: return "bool";
    case json_type_double:
    case json_type_int: return "number";
    case json_type_array: return "array";
    case json_type_object: return "object";
    case json_type_string: return "string";
    default: return "null";
    }
}

int br_json_type_cause(br_json *value, const char *field, const char *expected, char **cause)
{
    char message[512];
    if (field) snprintf(message, sizeof(message),
        "json: cannot unmarshal %s into Go struct field %s of type %s", type_word(value), field, expected);
    else snprintf(message, sizeof(message),
        "json: cannot unmarshal %s into Go value of type %s", type_word(value), expected);
    *cause = strdup(message);
    return *cause ? 0 : -1;
}

bool br_json_field_name(br_slice name, const char *expected)
{
    size_t at = 0;
    for (size_t i = 0; expected[i]; ++i) {
        if (at == name.len) return false;
        unsigned char c = name.data[at++];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c == (unsigned char)expected[i]) continue;
        if (expected[i] == 's' && c == 0xc5 && at < name.len && name.data[at] == 0xbf) { ++at; continue; }
        return false;
    }
    return at == name.len;
}

static int member_value(br_slice body, size_t *at, br_json **out)
{
    struct json_tokener *tokener = json_tokener_new_ex(10001);
    if (!tokener) return -1;
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT | JSON_TOKENER_ALLOW_TRAILING_CHARS);
    *out = json_tokener_parse_ex(tokener, (const char *)body.data + *at, (int)(body.len - *at));
    int rc = json_tokener_get_error(tokener) == json_tokener_success ? 0 : -1;
    *at += json_tokener_get_parse_end(tokener);
    json_tokener_free(tokener);
    return rc;
}

br_slice br_json_text(br_json *value)
{
    return value ? (br_slice){(const unsigned char *)json_object_get_string(value),
                              (size_t)json_object_get_string_len(value)} :
                   (br_slice){(const unsigned char *)"", 0};
}

int br_json_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    if (object.len > INT_MAX) return -1;
    size_t at = 0;
    while (at < object.len && json_space(object.data[at])) ++at;
    if (at == object.len || object.data[at++] != '{') return -1;
    while (at < object.len) {
        while (at < object.len && (json_space(object.data[at]) || object.data[at] == ',')) ++at;
        if (at == object.len || object.data[at] == '}') break;
        br_json *name = NULL, *value = NULL;
        if (member_value(object, &at, &name) != 0 || !name) { json_object_put(name); return -1; }
        while (at < object.len && json_space(object.data[at])) ++at;
        if (at == object.len || object.data[at++] != ':') { json_object_put(name); return -1; }
        while (at < object.len && json_space(object.data[at])) ++at;
        size_t begin = at;
        if (member_value(object, &at, &value) != 0) {
            json_object_put(name); json_object_put(value); return -1;
        }
        br_slice encoded_value = {object.data + begin, at - begin};
        int rc = callback(user, br_json_text(name), value, encoded_value);
        json_object_put(name);
        json_object_put(value);
        if (rc) return rc;
    }
    return 0;
}
