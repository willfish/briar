/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar_decoders.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned cases, assertions, failures;
static const char *current;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL UTF16 %s:%d: %s\n", current, __LINE__, #expr); ++failures; \
} } while (0)

static void check(const char *name, const unsigned char *input, size_t len,
                  const char *expected, bool applies)
{
    current = name; ++cases;
    unsigned char *original = len ? malloc(len) : NULL;
    if (len) memcpy(original, input, len);
    br_bytes out = {0};
    bool applied = false;
    char *error = NULL;
    CHECK(br_utf16_decode((br_slice){input, len}, &out, &applied, &error) == 0);
    CHECK(error == NULL);
    CHECK(applied == applies);
    if (applies) {
        CHECK(out.data != input);
        CHECK(out.len == strlen(expected));
        CHECK(out.len == strlen(expected) && !memcmp(out.data, expected, out.len));
    } else CHECK(out.data == NULL && out.len == 0);
    CHECK(!len || !memcmp(input, original, len));
    free(out.data); free(error); free(original);
}

#define MATCH(name, input, expected) check(name, (const unsigned char *)(input), sizeof(input) - 1, expected, true)
#define NONE(name, input) check(name, (const unsigned char *)(input), sizeof(input) - 1, NULL, false)

int main(void)
{
    MATCH("little endian", "a\0b\0y\0s\0s\0a\0l\0e\0", "abyssale");
    MATCH("big endian", "\0a\0b\0y\0s\0s\0a\0l\0e", "abyssale");
    MATCH("LE buffer before BE", "A\0\0BC\0", "ACB");
    MATCH("little endian BOM ignored", "\xff\xfe" "A\0B\0", "AB");
    MATCH("big endian BOM ignored", "\xfe\xff" "\0A\0B", "AB");
    MATCH("only printable ASCII", "A\0\n\0 \0\x7f\0B\0", "A B");
    MATCH("high bytes discarded", "\xe9\0\0\xe9" "A\0", "A");
    MATCH("odd last byte ignored", "A\0Z", "A");
    MATCH("fixed pair alignment", "\xff" "A\0B\0", "B");
    MATCH("spaces retained", " \0\0 ", "  ");
    NONE("plain ASCII", "ordinary text");
    NONE("empty", "");
    NONE("one byte", "A");
    NONE("zero pair", "\0\0");
    NONE("control pairs", "\n\0\0\r");
    NONE("surrogates not converted", "\x3d\xd8\x00\xde");

    current = "invalid arguments"; ++cases;
    br_bytes out = {0}; bool applied = true; char *error = NULL;
    CHECK(br_utf16_decode((br_slice){NULL, 3}, &out, &applied, &error) != 0);
    CHECK(error && !applied && !out.data && !out.len);
    free(error); error = NULL;
    CHECK(br_utf16_decode((br_slice){NULL, 0}, NULL, &applied, &error) != 0);
    CHECK(error && !applied);
    free(error); error = NULL;
    CHECK(br_utf16_decode((br_slice){NULL, 0}, &out, NULL, &error) != 0);
    CHECK(error && !out.data && !out.len);
    free(error);
    printf("UTF16: %u cases, %u assertions, %u failures\n", cases, assertions, failures);
    return failures ? 1 : 0;
}
