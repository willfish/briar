/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../support/detector_test.h"

static void expect_capture(const br_captures *values, size_t at, br_slice expected)
{
    br_slice value = br_captures_at(values, at);
    CHECK(value.len == expected.len && !memcmp(value.data, expected.data, expected.len));
    CHECK(values->items[at][value.len] == '\0');
}

int main(void)
{
    static const unsigned char first[] = {'a', 0, 'b'}, second[] = {'a', 0, 'c'};
    br_slice a = {first, sizeof(first)}, b = {second, sizeof(second)};
    br_captures values = {0};
    char *error = NULL;
    CHECK(br_captures_push(&values, a, true, &error) == 0 && !error);
    CHECK(br_captures_push(&values, b, true, &error) == 0 && !error);
    CHECK(br_captures_push(&values, a, true, &error) == 0 && !error);
    CHECK(values.len == 2);
    expect_capture(&values, 0, a);
    expect_capture(&values, 1, b);
    CHECK(br_captures_push(&values, (br_slice){first, 1}, true, &error) == 0);
    CHECK(values.len == 3);
    expect_capture(&values, 2, (br_slice){first, 1});
    for (size_t i = 0; i < 10; ++i)
        CHECK(br_captures_push(&values, a, false, &error) == 0 && !error);
    CHECK(values.len == 13 && values.cap >= values.len);
    expect_capture(&values, 1, b);
    expect_capture(&values, 12, a);
    br_captures_clear(&values);
    CHECK(!values.items && !values.lengths && !values.len && !values.cap);

    br_regex *regex = NULL;
    CHECK(br_regex_compile("(a\\x00[b-c])", &regex, &error) == 0 && !error);
    static const unsigned char input[] = {'a', 0, 'b', ' ', 'a', 0, 'c', ' ', 'a', 0, 'b'};
    CHECK(br_captures_find(regex, (br_slice){input, sizeof(input)}, &values, true, &error) == 0);
    CHECK(!error && values.len == 2);
    expect_capture(&values, 0, a);
    expect_capture(&values, 1, b);
    br_captures_clear(&values);
    CHECK(br_captures_find(regex, (br_slice){input, sizeof(input)}, &values, false, &error) == 0);
    CHECK(!error && values.len == 3);
    expect_capture(&values, 2, a);
    br_captures_clear(&values);
    br_regex_free(regex);
    return test_finish("Owned byte captures");
}
