/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/gcp_json.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})

static void quoted(br_slice input, br_slice expected)
{
    size_t measured = 0, written = 0; char *error = NULL;
    CHECK(br_gcp_json_string(input, NULL, 0, &measured, &error) == 0 && !error && measured == expected.len);
    unsigned char *out = malloc(measured + 1); CHECK(out); out[measured] = 0xa5;
    CHECK(br_gcp_json_string(input, out, measured, &written, &error) == 0 && !error && written == measured);
    CHECK(!memcmp(out, expected.data, expected.len) && out[measured] == 0xa5); free(out);
}

int main(void)
{
    /* Independent pinned-Go source/probe goldens, including the distinct
     * decode-then-marshal and direct-invalid-string paths. No transport. */
    quoted(TEXT("<>&\xe2\x80\xa8\xe2\x80\xa9\0\a\v/\x7f"), TEXT("\"\\u003c\\u003e\\u0026\\u2028\\u2029\\u0000\\u0007\\u000b/\x7f\""));
    quoted(TEXT("\"\\\b\f\n\r\t"), TEXT("\"\\\"\\\\\\b\\f\\n\\r\\t\""));
    quoted(TEXT("\xff"), TEXT("\"\\ufffd\""));
    quoted(TEXT("\xef\xbf\xbd"), TEXT("\"\xef\xbf\xbd\""));
    const struct { br_slice document, expected; bool repaired; } cases[] = {
        {TEXT("\"\xff\""), TEXT("\xef\xbf\xbd"), true},
        {TEXT("\"\\ud800\""), TEXT("\xef\xbf\xbd"), false},
        {TEXT("\"\\u0000x\""), TEXT("\0x"), false},
        {TEXT("\"valid-\xc3\xa9\""), TEXT("valid-\xc3\xa9"), false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_json *value = NULL; char *error = NULL; br_slice text; br_bytes repair = {0};
        CHECK(br_json_document(cases[i].document, &value, &error) == 0 && !error);
        br_slice original = br_json_text(value);
        CHECK(br_gcp_json_text(value, &text, &repair, &error) == 0 && !error);
        CHECK(text.len == cases[i].expected.len && !memcmp(text.data, cases[i].expected.data, text.len));
        CHECK((repair.data != NULL) == cases[i].repaired);
        if (!repair.data) CHECK(text.data == original.data);
        free(repair.data); json_object_put(value);
    }
    const char *const names[] = {"client_id", "client_secret", "refresh_token", "type"};
    const br_slice values[] = {TEXT("<>&"), TEXT("\0"), TEXT(""), TEXT("authorized_user")};
    br_bytes object = {0}; char *error = NULL;
    CHECK(br_gcp_json_object(names, values, 4, &object, &error) == 0 && !error);
    static const char expected[] = "{\"client_id\":\"\\u003c\\u003e\\u0026\",\"client_secret\":\"\\u0000\",\"refresh_token\":\"\",\"type\":\"authorized_user\"}";
    CHECK(object.len == sizeof(expected) - 1 && !memcmp(object.data, expected, sizeof(expected))); free(object.data);
    CHECK(br_gcp_json_object(NULL, NULL, 0, &object, &error) == 0 && !error);
    CHECK(object.len == 2 && !memcmp(object.data, "{}", 3)); free(object.data);
    printf("Google credential JSON strings: %zu assertions, 0 failures; pinned-source codec goldens, no I/O\n", test_assertions);
    return 0;
}
