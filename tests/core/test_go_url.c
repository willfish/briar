/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/go_url.h"
#include "../support/detector_test.h"

#define SLICE(s) (br_slice){(const unsigned char *)(s), sizeof(s) - 1}

static void decode(br_slice raw, bool query, br_slice expected, bool wanted)
{
    br_bytes bytes = {0}; bool valid = false; char *error = NULL;
    CHECK(br_go_url_decode(raw, query, &bytes, &valid, &error) == 0 && !error && valid == wanted);
    if (valid) CHECK(bytes.len == expected.len && (!bytes.len || !memcmp(bytes.data, expected.data, bytes.len)));
    else CHECK(!bytes.data && !bytes.len);
    free(bytes.data);
}

static void query(br_slice raw, br_slice key, br_slice expected)
{
    br_bytes value = {0}; char *error = NULL;
    CHECK(br_go_url_query_get(raw, key, &value, &error) == 0 && !error);
    CHECK(value.len == expected.len && (!value.len || !memcmp(value.data, expected.data, value.len)));
    if (value.data) CHECK(value.data[value.len] == 0);
    free(value.data);
}

int main(void)
{
    decode(SLICE("a+b%2Fc%00d"), false, SLICE("a+b/c\0d"), true);
    decode(SLICE("a+b%2Fc%00d"), true, SLICE("a b/c\0d"), true);
    decode(SLICE("%ff%80"), false, SLICE("\xff\x80"), true);
    decode(SLICE("%"), true, SLICE(""), false);
    decode(SLICE("%GG"), false, SLICE(""), false);
    decode((br_slice){0}, true, SLICE(""), true);
    query(SLICE("user=first&user=second"), SLICE("user"), SLICE("first"));
    query(SLICE("user=&user=second"), SLICE("user"), SLICE(""));
    query(SLICE("%75ser=Name+One&user=second"), SLICE("user"), SLICE("Name One"));
    query(SLICE("user=%GG&user=valid"), SLICE("user"), SLICE("valid"));
    query(SLICE("user=bad;part&user=valid"), SLICE("user"), SLICE("valid"));
    query(SLICE("user=one%3Btwo"), SLICE("user"), SLICE("one;two"));
    query(SLICE("user\0name=x"), SLICE("user\0name"), SLICE("x"));
    query(SLICE("=value"), SLICE(""), SLICE("value"));
    query(SLICE("password=a%00b"), SLICE("password"), SLICE("a\0b"));
    query(SLICE("USER=upper&user=lower"), SLICE("user"), SLICE("lower"));
    query(SLICE("missing=other"), SLICE("user"), SLICE(""));
    unsigned char *many = malloc(10007); CHECK(many);
    memset(many, '&', 9999); memcpy(many + 9999, "user=v", 6);
    query((br_slice){many, 10005}, SLICE("user"), SLICE("v"));
    memset(many, '&', 10000); memcpy(many + 10000, "user=v", 6);
    query((br_slice){many, 10006}, SLICE("user"), SLICE(""));
    free(many);

    const struct { const char *input, *host; bool user, password; } cases[] = {
        {"//Name:p%40ss@Host:05432/db%00x?user=override", "Host:05432", true, true},
        {"https://a:b:443/x", "a:b:443", false, false},
        {"//[::ffff:192.0.2.1]:999999999999/x", "[::ffff:192.0.2.1]:999999999999", false, false},
        {"//[fe80::1%25zone]/db", "[fe80::1%zone]", false, false},
        {"opaque:%GG?user=A", "", false, false},
        {"//user@host/db", "host", true, false},
        {"//user:@host/db", "host", true, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_go_url_parts parts = {0}; br_go_url_error ordinary = {0}; char *error = NULL;
        br_slice input = {(const unsigned char *)cases[i].input, strlen(cases[i].input)};
        CHECK(br_go_url_parse(input, &parts, &ordinary, &error) == 0 && !error && ordinary.kind == BR_GO_URL_OK);
        CHECK(parts.host.len == strlen(cases[i].host) && (!parts.host.len || !memcmp(parts.host.data, cases[i].host, parts.host.len)));
        CHECK(parts.has_user == cases[i].user && parts.has_password == cases[i].password);
        if (!i) {
            decode(parts.raw_user, false, SLICE("Name"), true);
            decode(parts.raw_password, false, SLICE("p@ss"), true);
            decode(parts.raw_path, false, SLICE("/db\0x"), true);
            query(parts.raw_query, SLICE("user"), SLICE("override"));
        }
        br_go_url_clear(&parts); br_go_url_clear(&parts);
    }
    const char *invalid[] = {"//host/a%GG", "//host/#bad%GG", "//%00host/db", "//[127.0.0.1]/db", "//host:abc/db"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        br_go_url_parts parts = {0}; br_go_url_error ordinary = {0}; char *error = NULL;
        CHECK(br_go_url_parse((br_slice){(const unsigned char *)invalid[i], strlen(invalid[i])}, &parts, &ordinary, &error) == 0 && !error && ordinary.kind != BR_GO_URL_OK);
        br_go_url_clear(&parts);
    }
    return test_finish("Selected Go URL parts/decoded bytes/query first-values and whole-map limit");
}
