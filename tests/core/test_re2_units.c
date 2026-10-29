/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/re2_units.h"
#include "../../src/utf8.h"
#include "../support/detector_test.h"

int main(void)
{
    const struct { unsigned char bytes[5]; size_t len, width; } cases[] = {
        {{0}, 1, 1}, {{'\n'}, 1, 1}, {{'\v'}, 1, 1}, {{0x7f}, 1, 1},
        {{0xc2,0x80}, 2, 2}, {{0xdf,0xbf}, 2, 2},
        {{0xe0,0x80,0x80}, 3, 3}, {{0xed,0xa0,0x80}, 3, 3},
        {{0xef,0xbf,0xbd}, 3, 3}, {{0xf0,0x80,0x80,0x80}, 4, 4},
        {{0xf4,0x90,0x80,0x80}, 4, 4}, {{0xf4,0xbf,0xbf,0xbf}, 4, 4},
        {{0xc0,0x80}, 2, 0}, {{0xc1,0xbf}, 2, 0}, {{0x80}, 1, 0},
        {{0xff}, 1, 0}, {{0xf5,0x80,0x80,0x80}, 4, 0},
        {{0xe0,0x7f,0x80}, 3, 0}, {{0xe0,0x80,0xff}, 3, 0},
        {{0xe0,0x80}, 2, 0}, {{0xf0,0x80,0x80}, 3, 0},
        {{0xed,0xa0,0x80,0x80}, 4, 3},
    };
    CHECK(br_re2_any_unit_width((br_slice){0}) == 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_slice s = {cases[i].bytes, cases[i].len};
        CHECK(br_re2_any_unit_width(s) == cases[i].width);
        if (cases[i].width > 1) {
            for (size_t n = 0; n < cases[i].width; ++n)
                CHECK(br_re2_any_unit_width((br_slice){s.data, n}) == 0);
        }
    }
    uint32_t rune = 0;
    CHECK(br_utf8_rune((br_slice){(const unsigned char *)"\xed\xa0\x80", 3}, &rune) == 0);
    CHECK(br_utf8_rune((br_slice){(const unsigned char *)"\xef\xbf\xbd", 3}, &rune) == 3 && rune == 0xfffd);
    CHECK(br_re2_any_unit_width((br_slice){(const unsigned char *)"\xed\xa0\x80\x80", 4}) == 3);
    CHECK(br_re2_any_unit_width((br_slice){(const unsigned char *)"\x80", 1}) == 0);
    return test_finish("Selected RE2 optimized any-unit bytes, not Unicode decoding");
}
