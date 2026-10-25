/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar_decoders.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned cases, assertions, failures;
static const char *current;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL escaped Unicode %s:%d: %s\n", current, __LINE__, #expr); ++failures; \
} } while (0)

static void check(const char *name, const unsigned char *input, size_t len,
                  const unsigned char *expected, size_t expected_len, bool applies)
{
    current = name; ++cases;
    unsigned char *original = len ? malloc(len) : NULL;
    if (len) memcpy(original, input, len);
    br_bytes out = {0}; bool applied = false; char *error = NULL;
    CHECK(br_escaped_unicode_decode((br_slice){input, len}, &out, &applied, &error) == 0);
    CHECK(error == NULL);
    CHECK(applied == applies);
    if (applies) {
        CHECK(out.data != input);
        CHECK(out.len == expected_len);
        CHECK(out.len == expected_len && !memcmp(out.data, expected, expected_len));
    } else CHECK(out.data == NULL && out.len == 0);
    CHECK(!len || !memcmp(input, original, len));
    free(out.data); free(error); free(original);
}

#define MATCH(name, input, expected) check(name, (const unsigned char *)(input), sizeof(input) - 1, \
    (const unsigned char *)(expected), sizeof(expected) - 1, true)
#define NONE(name, input) check(name, (const unsigned char *)(input), sizeof(input) - 1, NULL, 0, false)

int main(void)
{
    MATCH("ordinary escape", "prefix \\u0041 suffix", "prefix A suffix");
    MATCH("double slash escape", "\\\\u0041", "A");
    MATCH("triple slash find position", "\\\\" "\\u0041", "\\A");
    MATCH("escape u case insensitive", "\\U0041", "A");
    MATCH("long scalar", "\\U0001F600", "\xf0\x9f\x98\x80");
    MATCH("long wins priority", "\\u0042 \\U00000041", "\\u0042 A");
    MATCH("invalid long still wins", "\\UFFFFFFFF \\u0041", "\\UFFFFFFFF \\u0041");
    MATCH("brace variable digits", "\\u{41}\\u{0042}", "AB");
    MATCH("brace priority over perl", "\\x{42} \\u{41}", "\\x{42} A");
    MATCH("perl", "\\x{41}", "A");
    MATCH("HTML hex", "&#x41;&#x0042;", "AB");
    MATCH("HTML before percent", "%u0042 &#x41;", "%u0042 A");
    MATCH("percent", "%u0041%u0042", "AB");
    MATCH("surrogate becomes RuneError", "\\uD800", "\xef\xbf\xbd");
    MATCH("embedded NUL", "x\\u0000y", "x\0y");
    MATCH("maximum scalar", "\\u{10ffff}", "\xf4\x8f\xbf\xbf");
    MATCH("out of range syntax applied", "\\u{110000}", "\\u{110000}");
    MATCH("code points consume space", "U+0041 U+0042", "AB");
    MATCH("code point punctuation restored", "U+0041!z", "A!z");
    MATCH("code point newline untouched", "U+0041\n", "A\n");
    MATCH("code point optional byte behavior", "U+0041\xc3\xa9", "A\xa9");
    MATCH("code point FindAll advancement", "U+0041U+0042", "AU+0042");
    MATCH("CSS whitespace consumed", "\\41 \\42 ", "AB");
    MATCH("CSS slash delimiter consumed", "\\41\\42 ", "A42 ");
    MATCH("CSS EOF", "\\41", "A");
    MATCH("malformed UTF8 outside match", "\xff" "\\u0041", "\xff" "A");
    NONE("code point ASCII word boundary", "xU+0041");
    NONE("lowercase code point prefix", "u+0041");
    NONE("uppercase HTML X", "&#X41;");
    NONE("uppercase percent U", "%U0041");
    NONE("CSS needs delimiter", "\\41g");
    NONE("CSS vertical tab is not slash-s", "\\41\v");
    NONE("brace zero digits", "\\u{}");
    NONE("brace too many digits", "\\u{0000041}");
    NONE("invalid hex", "\\uZZZZ");
    NONE("ordinary text", "ordinary text");
    NONE("empty", "");

    current = "invalid arguments"; ++cases;
    br_bytes out = {0}; bool applied = true; char *error = NULL;
    CHECK(br_escaped_unicode_decode((br_slice){NULL, 1}, &out, &applied, &error) != 0);
    CHECK(error && !applied && !out.data && !out.len);
    free(error); error = NULL;
    CHECK(br_escaped_unicode_decode((br_slice){NULL, 0}, NULL, &applied, &error) != 0);
    CHECK(error && !applied);
    free(error); error = NULL;
    CHECK(br_escaped_unicode_decode((br_slice){NULL, 0}, &out, NULL, &error) != 0);
    CHECK(error && !out.data && !out.len);
    free(error);
    printf("Escaped Unicode: %u cases, %u assertions, %u failures\n", cases, assertions, failures);
    return failures ? 1 : 0;
}
