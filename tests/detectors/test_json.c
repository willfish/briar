/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

typedef struct { size_t elements, members; br_json *retained; } visits;

static int member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    visits *seen = user;
    CHECK(name.len == 4 && !memcmp(name.data, "name", 4));
    if (!seen->members) {
        CHECK(value && json_object_is_type(value, json_type_string));
        CHECK(!strcmp(json_object_get_string(value), "first"));
        CHECK(encoded.len == 7 && !memcmp(encoded.data, "\"first\"", 7));
    } else {
        CHECK(!value && encoded.len == 4 && !memcmp(encoded.data, "null", 4));
    }
    ++seen->members;
    return 0;
}

static int element(void *user, size_t index, br_json *value, br_slice encoded)
{
    visits *seen = user;
    CHECK(index == seen->elements++);
    if (index == 0) {
        CHECK(value && json_object_is_type(value, json_type_object));
        /* Native DOM lookup collapses this duplicate; original bytes must not. */
        CHECK(br_json_each_member(encoded, member, seen) == 0);
    } else if (index == 1) {
        CHECK(!value && encoded.len == 4 && !memcmp(encoded.data, "null", 4));
    } else {
        CHECK(index == 2 && value && json_object_is_type(value, json_type_string));
        CHECK(encoded.len >= 6 && !memcmp(encoded.data, "\"tail\"", 6));
        for (size_t i = 6; i < encoded.len; ++i) CHECK(encoded.data[i] == ' ');
        seen->retained = json_object_get(value);
    }
    return 0;
}

static int stop(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)value;
    (void)encoded;
    size_t *count = user;
    CHECK(index == (*count)++);
    return index == 1 ? 19 : 0;
}

static int unicode_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    visits *seen = user;
    CHECK(index == seen->elements++);
    if (index < 2) {
        const char *expected = index ? "\xc3\xa9" : "\xce\xbb";
        br_slice text = br_json_text(value);
        CHECK(value && json_object_is_type(value, json_type_string));
        CHECK(text.len == 2 && !memcmp(text.data, expected, 2));
        const char *original = index ? "\"\\u00e9\"" : "\"\xce\xbb\"";
        CHECK(encoded.len == strlen(original) && !memcmp(encoded.data, original, encoded.len));
    } else {
        CHECK(index == 2 && !value && encoded.len == 4 && !memcmp(encoded.data, "null", 4));
    }
    return 0;
}

static int unicode_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    visits *seen = user;
    size_t index = seen->members++;
    if (index < 2) {
        /* Raw and escaped spellings decode identically, in original order. */
        static const char expected[] = "i\xc5\xbf_available";
        CHECK(name.len == sizeof(expected) - 1 && !memcmp(name.data, expected, name.len));
        CHECK(br_json_field_name(name, "is_available"));
        if (!index) {
            CHECK(value && json_object_is_type(value, json_type_boolean) && json_object_get_boolean(value));
            CHECK(encoded.len == 4 && !memcmp(encoded.data, "true", 4));
        } else CHECK(!value && encoded.len == 4 && !memcmp(encoded.data, "null", 4));
    } else if (index == 2) {
        CHECK(name.len == 2 && !memcmp(name.data, "\xce\xbb", 2));
        br_slice text = br_json_text(value);
        CHECK(value && text.len == 2 && !memcmp(text.data, "\xc3\xa9", 2));
        CHECK(encoded.len == 4 && !memcmp(encoded.data, "\"\xc3\xa9\"", 4));
        seen->retained = json_object_get(value);
    } else {
        CHECK(index == 3 && name.len == 6 && !memcmp(name.data, "values", 6));
        CHECK(value && json_object_is_type(value, json_type_array));
        CHECK(br_json_each_element(encoded, unicode_element, seen) == 0);
    }
    return 0;
}

static int unicode_number_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    ++*(size_t *)user;
    if (name.len == 1 && name.data[0] == 'n') {
        static const char number[] = "18446744073709551616";
        CHECK(value && (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)));
        CHECK(encoded.len == sizeof(number) - 1 && !memcmp(encoded.data, number, encoded.len));
        CHECK(json_object_get_double(value) != 0); /* Never expose the shadow's zero. */
    } else {
        CHECK(name.len == 2 && !memcmp(name.data, "\xce\xbb", 2));
        br_slice string = br_json_text(value);
        CHECK(string.len == 2 && !memcmp(string.data, "\xc3\xa9", 2));
        CHECK(encoded.len == 4 && !memcmp(encoded.data, "\"\xc3\xa9\"", 4));
    }
    return 0;
}

int main(void)
{
    static const unsigned char kelvin[] = "wor\xe2\x84\xaaplace";
    CHECK(br_json_field_name((br_slice){kelvin, sizeof(kelvin) - 1}, "workplace"));
    static const unsigned char bytes[] = " [ {\"name\":\"first\",\"name\":null}, null, \"tail\" ] ";
    br_slice array = {bytes, sizeof(bytes) - 1};
    br_json *root = NULL;
    char *cause = NULL;
    CHECK(br_json_document(array, &root, &cause) == 0 && root && !cause);
    visits seen = {0};
    CHECK(br_json_each_element(array, element, &seen) == 0);
    CHECK(seen.elements == 3 && seen.members == 2 && seen.retained);
    json_object_put(root);
    CHECK(!strcmp(json_object_get_string(seen.retained), "tail"));
    json_object_put(seen.retained);
    size_t count = 0;
    CHECK(br_json_each_element(array, stop, &count) == 19 && count == 2);
    CHECK(br_json_each_element((br_slice){(const unsigned char *)"[]", 2}, stop, &count) == 0);
    CHECK(count == 2);
    static const unsigned char unicode[] =
        "{\"i\xc5\xbf_available\":true,\"i\\u017f_available\":null,\"\xce\xbb\":\"\xc3\xa9\",\"values\":[\"\xce\xbb\",\"\\u00e9\",null]}";
    br_slice object = {unicode, sizeof(unicode) - 1};
    CHECK(br_json_document(object, &root, &cause) == 0 && root && !cause);
    visits unicode_seen = {0};
    CHECK(br_json_each_member(object, unicode_member, &unicode_seen) == 0);
    CHECK(unicode_seen.members == 4 && unicode_seen.elements == 3 && unicode_seen.retained);
    json_object_put(root);
    br_slice retained = br_json_text(unicode_seen.retained);
    CHECK(retained.len == 2 && !memcmp(retained.data, "\xc3\xa9", 2));
    json_object_put(unicode_seen.retained);
    /* Validation shadows must combine both workarounds, regardless of which
     * native strict failure is encountered first, without replacing values. */
    const char *numbers[] = {
        "{\"\xce\xbb\":\"\xc3\xa9\",\"n\":18446744073709551616}",
        "{\"n\":18446744073709551616,\"\xce\xbb\":\"\xc3\xa9\"}",
    };
    for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        br_slice document = {(const unsigned char *)numbers[i], strlen(numbers[i])};
        CHECK(br_json_document(document, &root, &cause) == 0 && root && !cause);
        size_t members = 0;
        CHECK(br_json_each_member(document, unicode_number_member, &members) == 0 && members == 2);
        json_object_put(root);
    }
    static const unsigned char trailing[] = "\"\xce\xbb\" {}";
    br_slice string = {trailing, sizeof(trailing) - 1};
    size_t end = 0;
    CHECK(br_json_first_document(string, NULL, &root, &end, &cause) == 0 && root && !cause);
    CHECK(json_object_is_type(root, json_type_string) && json_object_get_string_len(root) == 2);
    CHECK(!memcmp(json_object_get_string(root), "\xce\xbb", 2) && (end == 4 || end == 5));
    json_object_put(root);
    CHECK(br_json_document(string, &root, &cause) == 1 && !root && cause);
    CHECK(!strcmp(cause, "invalid character '{' after top-level value"));
    free(cause); cause = NULL;
    const struct { const char *body, *read_error, *cause; } failures[] = {
        {"{\"v\":\"\xce\xbb\",", NULL, "unexpected EOF"},
        {"{\"v\":\"\xce\xbb\",", "synthetic read failure", "synthetic read failure"},
        {"{\"v\":\"\xce\xbb\",!}", NULL, "invalid character '!' looking for beginning of object key string"},
        {"\"\xce\xbb\"", "synthetic read failure", "synthetic read failure"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        br_slice document = {(const unsigned char *)failures[i].body, strlen(failures[i].body)};
        CHECK(br_json_first_document(document, failures[i].read_error, &root, &end, &cause) == 1 && !root && cause);
        CHECK(!strcmp(cause, failures[i].cause));
        free(cause); cause = NULL;
    }
    return test_finish("JSON source spans, raw UTF8 names/values, nulls and callback ownership");
}
