/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared response-document parsing and ordered member visits. */
#include "json.h"

#include <json-c/json.h>
#include <json-c/json_util.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Syntax is already validated. Check ORIGINAL number tokens, not json-c's
 * possibly saturated values, including nested and overwritten map entries. */
int br_json_check_float64_numbers(br_slice document, char **cause)
{
    *cause = NULL;
    bool quoted = false, escaped = false;
    for (size_t i = 0; i < document.len; ++i) {
        unsigned char c = document.data[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
            continue;
        }
        if (c == '"') { quoted = true; continue; }
        if (c != '-' && (c < '0' || c > '9')) continue;
        size_t begin = i;
        while (i < document.len) {
            c = document.data[i];
            if (!((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E')) break;
            ++i;
        }
        size_t len = i - begin;
        if (len == SIZE_MAX) return -1;
        char *token = malloc(len + 1);
        if (!token) return -1;
        memcpy(token, document.data + begin, len);
        token[len] = '\0';
        double number = 0;
        /* ERANGE alone is not rejection: Go accepts finite underflow to zero. */
        bool invalid = json_parse_double(token, &number) != 0 || !isfinite(number);
        if (invalid) {
            static const char prefix[] = "json: cannot unmarshal number ";
            static const char suffix[] = " into Go value of type float64";
            size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
            if (len > SIZE_MAX - overhead) { free(token); return -1; }
            *cause = malloc(overhead + len);
            if (*cause) {
                memcpy(*cause, prefix, sizeof(prefix) - 1);
                memcpy(*cause + sizeof(prefix) - 1, token, len);
                memcpy(*cause + sizeof(prefix) - 1 + len, suffix, sizeof(suffix));
            }
            free(token);
            return *cause ? 1 : -1;
        }
        free(token);
        --i; /* The outer loop still visits the token's following delimiter. */
    }
    return 0;
}

static bool json_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int decode_cause(char **cause, const char *message)
{
    *cause = strdup(message);
    return *cause ? 1 : -1;
}

static int invalid_character(br_slice body, size_t offset, const char *context, char **cause)
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
    snprintf(message, sizeof(message), "invalid character %s %s", byte, context);
    return decode_cause(cause, message);
}

static int syntax_cause(enum json_tokener_error code, br_slice body, size_t offset, char **cause)
{
    const char *context;
    switch (code) {
    case json_tokener_error_parse_object_key_name: context = "looking for beginning of object key string"; break;
    case json_tokener_error_parse_object_key_sep: context = "after object key"; break;
    case json_tokener_error_parse_object_value_sep: context = "after object key:value pair"; break;
    case json_tokener_error_parse_array: context = "after array element"; break;
    default: context = "looking for beginning of value"; break;
    }
    return invalid_character(body, offset, context, cause);
}

static bool digit(unsigned char c) { return c >= '0' && c <= '9'; }

/* Locate a complete JSON number without interpreting its magnitude. */
static size_t number_end(br_slice body, size_t at, bool *integer)
{
    size_t i = at;
    *integer = true;
    if (body.data[i] == '-') ++i;
    if (i == body.len || !digit(body.data[i])) return at;
    if (body.data[i] == '0') {
        ++i;
        if (i < body.len && digit(body.data[i])) return at;
    } else while (i < body.len && digit(body.data[i])) ++i;
    if (i < body.len && body.data[i] == '.') {
        *integer = false;
        if (++i == body.len || !digit(body.data[i])) return at;
        while (i < body.len && digit(body.data[i])) ++i;
    }
    if (i < body.len && (body.data[i] == 'e' || body.data[i] == 'E')) {
        *integer = false;
        ++i;
        if (i < body.len && (body.data[i] == '+' || body.data[i] == '-')) ++i;
        if (i == body.len || !digit(body.data[i])) return at;
        while (i < body.len && digit(body.data[i])) ++i;
    }
    return i;
}

/* json-c STRICT conflates integer range with JSON syntax. Validate range-limited
 * input using an offset-preserving shadow, never return the shadow's values. */
static int range_shadow(br_slice body, char **out)
{
    *out = malloc(body.len + 1);
    if (!*out) return -1;
    memcpy(*out, body.data, body.len);
    (*out)[body.len] = '\0';
    bool string = false, escape = false, changed = false;
    unsigned char previous = 0;
    for (size_t i = 0; i < body.len;) {
        unsigned char c = body.data[i];
        if (string) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') { string = false; previous = '"'; }
            ++i;
            continue;
        }
        if (c == '"') { string = true; ++i; continue; }
        if (json_space(c)) { ++i; continue; }
        bool boundary = !previous || previous == '[' || previous == '{' || previous == ':' || previous == ',';
        if (boundary && (c == '-' || digit(c))) {
            bool integer;
            size_t end = number_end(body, i, &integer);
            if (end != i) {
                if (integer) {
                    char saved = (*out)[end];
                    (*out)[end] = '\0';
                    errno = 0;
                    (void)strtoll(*out + i, NULL, 10);
                    bool outside = errno == ERANGE;
                    (*out)[end] = saved;
                    if (outside) {
                        memset(*out + i, ' ', end - i);
                        (*out)[i] = '0';
                        changed = true;
                    }
                }
                previous = body.data[end - 1];
                i = end;
                continue;
            }
        }
        previous = c;
        ++i;
    }
    if (!changed) { free(*out); *out = NULL; }
    return 0;
}

static int native_value(br_slice body, bool strict, bool finish, br_json **value,
                        enum json_tokener_error *code, size_t *offset, bool *incomplete)
{
    struct json_tokener *tokener = json_tokener_new_ex(10001);
    if (!tokener) return -1;
    json_tokener_set_flags(tokener, JSON_TOKENER_ALLOW_TRAILING_CHARS | (strict ? JSON_TOKENER_STRICT : 0));
    *value = json_tokener_parse_ex(tokener, body.data ? (const char *)body.data : "", (int)body.len);
    *code = json_tokener_get_error(tokener);
    *offset = json_tokener_get_parse_end(tokener);
    *incomplete = *code == json_tokener_continue;
    if (*incomplete && finish) {
        *value = json_tokener_parse_ex(tokener, " ", 1);
        *code = json_tokener_get_error(tokener);
    }
    json_tokener_free(tokener);
    return 0;
}

static int response_value(br_slice body, bool finish, br_json **value,
                          enum json_tokener_error *code, size_t *offset, bool *incomplete)
{
    int rc = native_value(body, true, finish, value, code, offset, incomplete);
    if (rc || *code != json_tokener_error_parse_number) return rc;
    char *shadow = NULL;
    if (range_shadow(body, &shadow) != 0) return -1;
    if (!shadow) return 0;
    br_json *validated = NULL;
    enum json_tokener_error checked;
    size_t end;
    bool partial;
    rc = native_value((br_slice){(const unsigned char *)shadow, body.len}, true, finish,
                      &validated, &checked, &end, &partial);
    if (!rc && checked == json_tokener_success) {
        json_object_put(*value);
        *value = NULL;
        /* Syntax is strict-validated; now decode ORIGINAL bytes using json-c's
         * native range handling. Typed numeric fields use encoded_value. */
        rc = native_value(body, false, finish, value, code, offset, incomplete);
    }
    json_object_put(validated);
    free(shadow);
    return rc;
}

int br_json_first_document(br_slice body, const char *read_error, br_json **out,
                            size_t *end, char **cause)
{
    *out = NULL;
    *end = 0;
    *cause = NULL;
    if (body.len > INT_MAX) return -1;
    br_json *value = NULL;
    enum json_tokener_error code;
    size_t offset;
    bool incomplete;
    if (response_value(body, !read_error, &value, &code, &offset, &incomplete) != 0) {
        json_object_put(value);
        return -1;
    }
    /* Go's stream decoder needs one more byte (or EOF) after a scalar string.
     * json-c closes it immediately; a terminal non-EOF read error still wins. */
    if (read_error && code == json_tokener_success && offset == body.len && body.len &&
        body.data[body.len - 1] == '"' && json_object_is_type(value, json_type_string)) {
        code = json_tokener_continue;
        incomplete = true;
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
        return rc;
    }
    *out = value;
    *end = incomplete ? body.len : offset;
    /* json-c STRICT still accepts non-JSON constants and leading-zero numbers. */
    bool string = false, escape = false;
    for (size_t i = 0; i < *end; ++i) {
        unsigned char c = body.data[i];
        if (string) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') string = false;
        } else if (c == '"') string = true;
        else if (c == '-' || digit(c)) {
            bool integer;
            size_t next = number_end((br_slice){body.data, *end}, i, &integer);
            if (next == i) {
                json_object_put(*out);
                *out = NULL;
                return syntax_cause(json_tokener_error_parse_unexpected, body, i, cause);
            }
            i = next - 1;
        } else if (c == 'N' || c == 'I' || c == 'i') {
            json_object_put(*out);
            *out = NULL;
            return syntax_cause(json_tokener_error_parse_unexpected, body, i, cause);
        }
    }
    return 0;
}

int br_json_document(br_slice body, br_json **out, char **cause)
{
    size_t end = 0;
    int rc = br_json_first_document(body, NULL, out, &end, cause);
    if (rc) {
        if (rc == 1 && (!strcmp(*cause, "EOF") || !strcmp(*cause, "unexpected EOF"))) {
            free(*cause);
            return decode_cause(cause, "unexpected end of JSON input");
        }
        return rc;
    }
    for (; end < body.len; ++end) {
        if (json_space(body.data[end])) continue;
        json_object_put(*out);
        *out = NULL;
        return invalid_character(body, end, "after top-level value", cause);
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
    enum json_tokener_error code;
    size_t offset;
    bool incomplete;
    int rc = response_value((br_slice){body.data + *at, body.len - *at}, false,
                            out, &code, &offset, &incomplete);
    if (rc) return rc;
    *at += offset;
    return code == json_tokener_success ? 0 : -1;
}

br_slice br_json_text(br_json *value)
{
    return value ? (br_slice){(const unsigned char *)json_object_get_string(value),
                              (size_t)json_object_get_string_len(value)} :
                   (br_slice){(const unsigned char *)"", 0};
}

int br_json_each_element(br_slice array, br_json_element_fn callback, void *user)
{
    if (array.len > INT_MAX) return -1;
    size_t at = 0, index = 0;
    while (at < array.len && json_space(array.data[at])) ++at;
    if (at == array.len || array.data[at++] != '[') return -1;
    while (at < array.len) {
        while (at < array.len && (json_space(array.data[at]) || array.data[at] == ',')) ++at;
        if (at == array.len || array.data[at] == ']') break;
        size_t begin = at;
        br_json *value = NULL;
        if (member_value(array, &at, &value) != 0) { json_object_put(value); return -1; }
        int rc = callback(user, index++, value, (br_slice){array.data + begin, at - begin});
        json_object_put(value);
        if (rc) return rc;
    }
    return 0;
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
