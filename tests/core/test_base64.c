/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar_decoders.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned cases, assertions, failures;
static const char *current;
#define CHECK(test) do { ++assertions; if (!(test)) { \
    fprintf(stderr, "FAIL Base64 %s:%d: %s\n", current, __LINE__, #test); \
    ++failures; } } while (0)

static void check(const char *name, const unsigned char *input, size_t len,
                  const unsigned char *expected, size_t expected_len, bool applies)
{
    current = name;
    ++cases;
    br_bytes out = {0};
    bool applied = false;
    char *error = NULL;
    unsigned char *original = len ? malloc(len) : NULL;
    if (len) memcpy(original, input, len);
    CHECK(br_base64_decode((br_slice){input, len}, &out, &applied, &error) == 0);
    CHECK(error == NULL);
    CHECK(applied == applies);
    if (applies) {
        CHECK(out.data != input);
        CHECK(out.len == expected_len);
        CHECK(out.len == expected_len && !memcmp(out.data, expected, expected_len));
    } else {
        CHECK(out.data == NULL && out.len == 0);
    }
    CHECK(!len || !memcmp(input, original, len));
    free(original);
    free(out.data);
    free(error);
}

#define MATCH(name, input, expected) check(name, (const unsigned char *)(input), \
    sizeof(input) - 1, (const unsigned char *)(expected), sizeof(expected) - 1, true)
#define NONE(name, input) check(name, (const unsigned char *)(input), \
    sizeof(input) - 1, NULL, 0, false)

int main(void)
{
    MATCH("standard", "before: YWJ5c3NhbGUgc3ludGhldGljIGtleQ== :after", "before: abyssale synthetic key :after");
    MATCH("raw URL", "YWJ5c3NhbGUgc3ludGhldGljIGtleQ", "abyssale synthetic key");
    MATCH("unpadded complete quartet", "YWJjZGVmZ2hpamtsbW5vcHFy", "abcdefghijklmnopqr");
    MATCH("standard alphabet slash", "YWE/YWE/YWE/YWE/YWE/YWE/", "aa?aa?aa?aa?aa?aa?");
    MATCH("URL alphabet underscore", "YWE_YWE_YWE_YWE_YWE_YWE_", "aa?aa?aa?aa?aa?aa?");
    NONE("mixed alphabets", "YWE_YWE/YWE/YWE/YWE/YWE/");
    NONE("threshold is strict", "YWJjZGVmZ2hpamtsbW5v");
    NONE("invalid remainder one", "YWJjZGVmZ2hpamtsbW5vA");
    MATCH("threshold precedes trimming", "=YWJjZGVmZ2hpamtsbW5v", "=abcdefghijklmno");
    MATCH("assignment", "KEY=YWJjZGVmZ2hpamtsbW5vcHFy", "KEY=abcdefghijklmnopqr");
    NONE("only first internal equals", "KEY=SECOND=YWJjZGVmZ2hpamtsbW5vcHFy");
    MATCH("leading end characters preserved", "+/_-==YWJjZGVmZ2hpamtsbW5vcHFy", "+/_-==abcdefghijklmnopqr");
    NONE("decoded non-ASCII rejected", "cHJlZml4OsOpOm1vcmUgYnl0ZXM=");
    MATCH("ASCII includes controls", "YQBifwoJDWFiY2RlZmdoaWprbG1ub3A=", "a\0b\x7f\n\t\rabcdefghijklmnop");
    MATCH("standard non-strict final bits", "YWJjZGVmZ2hpamtsbW5vcR==", "abcdefghijklmnoq");
    MATCH("URL non-strict final bits", "YWJjZGVmZ2hpamtsbW5vcR", "abcdefghijklmnoq");
    MATCH("duplicates", "YWJjZGVmZ2hpamtsbW5vcHFy : YWJjZGVmZ2hpamtsbW5vcHFy", "abcdefghijklmnopqr : abcdefghijklmnopqr");
    MATCH("invalid outside bytes preserved", "\xff:YWJjZGVmZ2hpamtsbW5vcHFy", "\xff:abcdefghijklmnopqr");
    MATCH("Unicode surrounding text", "\xc3\xa9:YWJjZGVmZ2hpamtsbW5vcHFy", "\xc3\xa9:abcdefghijklmnopqr");
    NONE("all trimmed", "=======================");
    NONE("empty", "");
    NONE("ordinary text", "ordinary text with no candidate");
    NONE("extra padding rejected", "YWJjZGVmZ2hpamtsbW5vcQ===");
    NONE("interior padding rejected", "YWJjZGVmZ2hpamtsbW5vcQ==A");

    current = "invalid arguments";
    ++cases;
    br_bytes out = {0};
    bool applied = true;
    char *error = NULL;
    CHECK(br_base64_decode((br_slice){NULL, 3}, &out, &applied, &error) != 0);
    CHECK(error != NULL && !applied && out.data == NULL && out.len == 0);
    free(error);
    error = NULL;
    CHECK(br_base64_decode((br_slice){NULL, 0}, NULL, &applied, &error) != 0);
    CHECK(error != NULL && !applied);
    free(error);
    error = NULL;
    CHECK(br_base64_decode((br_slice){NULL, 0}, &out, NULL, &error) != 0);
    CHECK(error != NULL && out.data == NULL && out.len == 0);
    free(error);

    printf("Base64: %u cases, %u assertions, %u failures\n", cases, assertions, failures);
    return failures ? 1 : 0;
}
