/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/go_unicode.h"
#include "../../src/utf8.h"

#include <stdio.h>
#include <string.h>

static size_t assertions, failures;
#define CHECK(condition) do { ++assertions; if (!(condition)) { \
    ++failures; fprintf(stderr, "Go Unicode check failed at line %d\n", __LINE__); \
} } while (0)

static void properties(void)
{
    static const struct { uint32_t rune; unsigned properties; } cases[] = {
        {'a', BR_GO_LOWER}, {'A', BR_GO_UPPER}, {'9', BR_GO_NUMBER},
        {'!', BR_GO_PUNCT}, {'$', BR_GO_SYMBOL}, {' ', BR_GO_SPACE},
        {0, 0}, {0x7f, 0}, {0x00b5, BR_GO_LOWER}, {0x00df, BR_GO_LOWER},
        {0x0100, BR_GO_UPPER}, {0x0101, BR_GO_LOWER}, /* Alternating range strides. */
        {0x01c5, 0}, /* Titlecase does not satisfy uppercase or lowercase. */
        {0x03b1, BR_GO_LOWER}, {0x03a9, BR_GO_UPPER},
        {0x0660, BR_GO_NUMBER}, {0x2160, BR_GO_NUMBER}, {0x00b2, BR_GO_NUMBER},
        {0x1d7ce, BR_GO_NUMBER}, /* Nd, Nl and No, including supplementary planes. */
        {0x2014, BR_GO_PUNCT}, {0x20ac, BR_GO_SYMBOL}, {0x1f600, BR_GO_SYMBOL},
        {0xfffd, BR_GO_SYMBOL}, {0x0301, 0},
        {0x1c89, 0}, {0x1c8a, 0}, /* Assigned case categories only in Unicode16. */
        {0x0085, BR_GO_SPACE}, {0x00a0, BR_GO_SPACE}, {0x1680, BR_GO_SPACE},
        {0x2000, BR_GO_SPACE}, {0x200a, BR_GO_SPACE}, {0x200b, 0},
        {0x2028, BR_GO_SPACE}, {0x2029, BR_GO_SPACE},
        {0x202f, BR_GO_SPACE}, {0x205f, BR_GO_SPACE}, {0x3000, BR_GO_SPACE},
        {0xd800, 0}, {0xdfff, 0}, {0x10ffff, 0}, {0x110000, 0}, {UINT32_MAX, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
        CHECK(br_go_unicode_properties(cases[i].rune) == cases[i].properties);
    for (uint32_t rune = 9; rune <= 13; ++rune)
        CHECK(br_go_unicode_properties(rune) == BR_GO_SPACE);
    CHECK(!(br_go_unicode_properties('!') & BR_GO_SPACE)); /* Do not fill source stride gaps. */
}

static void scalar_bytes(void)
{
    static const unsigned char original[] = {'a', 0, 0x7f, 0xc2, 0xa0, 0xce, 0xa9, 0xf0, 0x9f, 0x98, 0x80};
    static const uint32_t runes[] = {'a', 0, 0x7f, 0xa0, 0x3a9, 0x1f600};
    static const size_t widths[] = {1, 1, 1, 2, 2, 4};
    unsigned char input[sizeof(original)]; memcpy(input, original, sizeof(input));
    CHECK(br_utf8_valid((br_slice){input, sizeof(input)}));
    size_t at = 0;
    for (size_t i = 0; i < sizeof(runes) / sizeof(*runes); ++i) {
        uint32_t rune = UINT32_MAX;
        size_t width = br_utf8_rune((br_slice){input + at, sizeof(input) - at}, &rune);
        CHECK(width == widths[i] && rune == runes[i]); at += width;
    }
    CHECK(at == sizeof(input) && !memcmp(input, original, sizeof(input)));
    CHECK(br_utf8_valid((br_slice){0}));
    CHECK(!br_utf8_valid((br_slice){NULL, 1}));
    uint32_t empty = 123;
    CHECK(br_utf8_rune((br_slice){0}, &empty) == 0 && empty == 123);
}

static void invalid_encodings(void)
{
    static const struct { unsigned char bytes[4]; size_t len; } cases[] = {
        {{0x80}, 1}, {{0xff}, 1}, {{0xc0, 0xaf}, 2}, {{0xe2, 0x82}, 2},
        {{0xed, 0xa0, 0x80}, 3}, {{0xf4, 0x90, 0x80, 0x80}, 4},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_slice input = {cases[i].bytes, cases[i].len}; uint32_t rune = 123;
        CHECK(!br_utf8_valid(input));
        CHECK(br_utf8_rune(input, &rune) == 0 && rune == 123);
    }
    static const unsigned char replacement[] = {0xef, 0xbf, 0xbd}; uint32_t rune = 0;
    CHECK(br_utf8_valid((br_slice){replacement, sizeof(replacement)}));
    CHECK(br_utf8_rune((br_slice){replacement, sizeof(replacement)}, &rune) == 3 && rune == 0xfffd);
    CHECK(!br_utf8_rune((br_slice){replacement, sizeof(replacement)}, NULL));
}

int main(void)
{
    properties(); scalar_bytes(); invalid_encodings();
    printf("Pinned Go15 Unicode properties + original UTF8 scalars: %zu assertions, %zu failures\n", assertions, failures);
    return failures ? 1 : 0;
}
