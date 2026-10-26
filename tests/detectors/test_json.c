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

int main(void)
{
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
    return test_finish("JSON array source spans, nulls and callback ownership");
}
