/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/overlap.h"
#include "../support/detector_test.h"

static void compare(const void *current, size_t ncurrent, const void *earlier, size_t nearly, bool expected)
{
    bool similar = !expected;
    char *error = NULL;
    CHECK(br_overlap_similar((br_slice){current, ncurrent}, (br_slice){earlier, nearly}, &similar, &error) == 0);
    CHECK(!error && similar == expected);
}

int main(void)
{
    compare("", 0, "", 0, true);
    compare("a", 1, "", 0, false);
    compare("key", 3, "key", 3, true);
    compare("key", 3, "Key", 3, false);
    compare("1234567890", 10, "123456789x", 10, false); /* Exactly0.9 is not above0.9. */
    compare("12345678901", 11, "1234567890x", 11, true);
    compare("1234567890", 10, "12345678901", 11, true);
    compare("1234567890", 10, "123456789012", 12, false);
    char shorter[100], longer[111];
    memset(shorter, 'a', sizeof(shorter));
    memset(longer, 'a', sizeof(longer));
    compare(shorter, sizeof(shorter), longer, sizeof(longer), false); /* Byte gate is asymmetric. */
    compare(longer, sizeof(longer), shorter, sizeof(shorter), true);
    const char unicode_a[] = "123456789\xc3\xa9", unicode_b[] = "123456789\xc3\xa8";
    compare(unicode_a, sizeof(unicode_a) - 1, unicode_b, sizeof(unicode_b) - 1, false); /* Ten runes, not11 bytes. */
    const unsigned char invalid_a[] = {'1','2','3','4','5','6','7','8','9',0xff};
    const unsigned char invalid_b[] = {'1','2','3','4','5','6','7','8','9',0xfe};
    compare(invalid_a, sizeof(invalid_a), invalid_b, sizeof(invalid_b), true); /* Each bad byte becomes RuneError. */
    const unsigned char nul_a[] = {'a',0,'b'}, nul_b[] = {'a',0,'c'};
    compare(nul_a, sizeof(nul_a), nul_a, sizeof(nul_a), true);
    compare(nul_a, sizeof(nul_a), nul_b, sizeof(nul_b), false);
    return test_finish("Overlap byte gates and rune similarity");
}
