/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/jdbc_private.h"
#include "../support/detector_test.h"
#define S(s) (br_slice){(const unsigned char *)(s), sizeof(s) - 1}

static void same(br_bytes got, br_slice expected)
{
    CHECK(got.len == expected.len && (!got.len || !memcmp(got.data, expected.data, got.len)));
    if (got.data) CHECK(got.data[got.len] == 0);
}

static void accepted(br_slice dsn, br_slice user, br_slice password, br_slice address, br_slice database)
{
    br_jdbc_mysql_dsn out = {0}; br_jdbc_dsn_status status = BR_JDBC_DSN_REJECTED; char *error = NULL;
    CHECK(br_jdbc_mysql_parse_dsn(dsn, &out, &status, &error) == 0 && !error && status == BR_JDBC_DSN_ACCEPTED);
    same(out.user, user); same(out.password, password); same(out.address, address); same(out.database, database);
    br_jdbc_mysql_dsn_clear(&out); br_jdbc_mysql_dsn_clear(&out);
    CHECK(!out.user.data && !out.password.data && !out.address.data && !out.database.data);
}

static void rejected(br_slice dsn, const char *fatal)
{
    br_jdbc_mysql_dsn out = {0}; br_jdbc_dsn_status status = BR_JDBC_DSN_ACCEPTED; char *error = NULL;
    int rc = br_jdbc_mysql_parse_dsn(dsn, &out, &status, &error);
    CHECK(status == BR_JDBC_DSN_REJECTED && !out.user.data && !out.password.data && !out.address.data && !out.database.data);
    if (fatal) CHECK(rc != 0 && error && strstr(error, fatal));
    else CHECK(rc == 0 && !error);
    free(error); br_jdbc_mysql_dsn_clear(&out);
}

int main(void)
{
    accepted(S(""), S(""), S(""), S("127.0.0.1:3306"), S(""));
    accepted(S("/db"), S(""), S(""), S("127.0.0.1:3306"), S("db"));
    accepted(S("u:p@tcp(host)/db"), S("u"), S("p"), S("host:3306"), S("db"));
    accepted(S("u:pa:ss@tcp(host:weird)/db+name"), S("u"), S("pa:ss"), S("host:weird"), S("db+name"));
    accepted(S("u@tcp([::1])/d%2fb"), S("u"), S(""), S("[[::1]]:3306"), S("d/b"));
    accepted(S("u:p@tcp(::1)/db"), S("u"), S("p"), S("[::1]:3306"), S("db"));
    accepted(S("u:p@unix(/sock/path)/db"), S("u"), S("p"), S("/sock/path"), S("db"));
    accepted(S("u:p@tcp([not-IP]:x)/db"), S("u"), S("p"), S("[not-IP]:x"), S("db"));
    accepted(S("u:p@tcp(host:)/db"), S("u"), S("p"), S("host:"), S("db"));
    accepted(S("u:p@custom(host)/db"), S("u"), S("p"), S("host"), S("db"));
    accepted(S("u:p@tcp(host)/d%00b?unknown=a%00b;anything"), S("u"), S("p"), S("host:3306"), S("d\0b"));
    accepted(S("u\0x:p\0x@tcp(host)/db"), S("u\0x"), S("p\0x"), S("host:3306"), S("db"));
    const char *valid_params[] = {
        "strict", "interpolateParams=true&collation=gbk_bin&interpolateParams=false", "tls=%74rue", "tls=s\xe2\x84\xaaip-verify",
        "loc=UTC&loc=Local&loc=", "allowAllFiles=True&parseTime=FALSE", "serverPubKey=", "maxAllowedPacket=9223372036854775807", "maxAllowedPacket=-9223372036854775808"
    };
    for (size_t i = 0; i < sizeof(valid_params) / sizeof(valid_params[0]); ++i) {
        char *dsn = NULL; CHECK(asprintf(&dsn, "/db?%s", valid_params[i]) > 0);
        accepted((br_slice){(const unsigned char *)dsn, strlen(dsn)}, S(""), S(""), S("127.0.0.1:3306"), S("db")); free(dsn);
    }
    const char *durations[] = {"0", "-0", "+0", "-1ns", ".5s", "1.s", "1h2m", "1\xc2\xb5s", "1\xce\xbcs", "-9223372036854775808ns", "9223372036854775808ns9223372036854775808ns", "0.123456789012345678901234567890h"};
    for (size_t i = 0; i < sizeof(durations) / sizeof(durations[0]); ++i) {
        char *dsn = NULL; CHECK(asprintf(&dsn, "/db?timeout=%s", durations[i]) > 0);
        accepted((br_slice){(const unsigned char *)dsn, strlen(dsn)}, S(""), S(""), S("127.0.0.1:3306"), S("db")); free(dsn);
    }
    const char *invalid[] = {
        "noslash", "u:p@tcp(host/db", "u:p@custom/db", "/bad%", "/db?compress=0", "/db?parseTime=tRuE", "/db?unknown=%GG",
        "/db?interpolateParams=true&collation=gbk_bin", "/db?tls=%54RUE", "/db?tls=unknown", "/db?serverPubKey=unknown",
        "/db?loc=%2FUTC", "/db?loc=x..y", "/db?loc=..&strict=1", "/db?timeout=bad&strict=1", "/db?parseTime=bad&strict=1",
        "/db?maxAllowedPacket=9223372036854775808", "/db?maxAllowedPacket=-9223372036854775809", "/db?maxAllowedPacket=1_0", "/db?maxAllowedPacket=+", "/db?maxAllowedPacket= 1"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) rejected((br_slice){(const unsigned char *)invalid[i], strlen(invalid[i])}, NULL);
    const char *bad_durations[] = {"", "00", "1", "-", "1e3s", "9223372036854775808ns", "-9223372036854775809ns", "1 s", "1%C2%B5s", "NaN"};
    for (size_t i = 0; i < sizeof(bad_durations) / sizeof(bad_durations[0]); ++i) {
        char *dsn = NULL; CHECK(asprintf(&dsn, "/db?readTimeout=%s", bad_durations[i]) > 0);
        rejected((br_slice){(const unsigned char *)dsn, strlen(dsn)}, NULL); free(dsn);
    }
    rejected(S("/db?strict=0"), "strict-mode panic");
    rejected(S("/db?collation=gbk_bin&interpolateParams=true&strict=1"), "strict-mode panic");
    rejected(S("/bad%?strict=1"), "strict-mode panic");
    rejected(S("/db?tls=unknown&strict=1"), "strict-mode panic");
    rejected(S("/db?loc=Europe%2FLondon"), "time-location lookup");
    rejected(S("/db?loc=Europe%2FLondon&strict=1"), "time-location lookup");
    br_jdbc_mysql_dsn_clear(NULL);
    return test_finish("MySQL selected driver DSN fields/ordered validation/duration/Atoi/lexical addresses/guarded dependencies");
}
