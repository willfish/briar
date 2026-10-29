/* SPDX-License-Identifier: MPL-2.0 */
/* Go MySQL Driver - A MySQL-Driver for Go's database/sql package
 * Copyright 2012, 2014, 2016 The Go-MySQL-Driver Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/. See LICENSES/MPL-2.0-go-sql-driver-mysql.txt.
 * C projection of selected v1.8.1 dsn.go, utils.readBool and unsafeCollations.
 * Selected Go 1.26.7 duration, integer and address rules: Copyright 2009, 2010
 * The Go Authors. All rights reserved. See LICENSES/BSD-3-Clause-Go.txt.
 * No files, location database, TLS registry, public key store or network I/O. */
#include "jdbc_private.h"
#include "../go_url.h"
#include "../go_unicode.h"
#include "../utf8.h"
#include <stdlib.h>
#include <string.h>

#define LIT(s) (br_slice){(const unsigned char *)(s), sizeof(s) - 1}

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice part(br_slice s, size_t at, size_t len)
{
    return (br_slice){s.data ? s.data + at : NULL, len};
}

static bool equal(br_slice a, const char *b)
{
    size_t n = strlen(b);
    return a.len == n && (!n || !memcmp(a.data, b, n));
}

static size_t find(br_slice s, unsigned char c)
{
    const unsigned char *p = s.len ? memchr(s.data, c, s.len) : NULL;
    return p ? (size_t)(p - s.data) : SIZE_MAX;
}

static size_t last(br_slice s, unsigned char c)
{
    for (size_t i = s.len; i; --i) if (s.data[i - 1] == c) return i - 1;
    return SIZE_MAX;
}

static int copy(br_slice s, br_bytes *out)
{
    if (!s.len) return 0;
    if (s.len == SIZE_MAX || !(out->data = malloc(s.len + 1))) return -1;
    memcpy(out->data, s.data, s.len); out->data[s.len] = 0; out->len = s.len;
    return 0;
}

static bool read_bool(br_slice value, bool *out)
{
    if (equal(value, "1") || equal(value, "true") || equal(value, "TRUE") || equal(value, "True")) {
        *out = true; return true;
    }
    if (equal(value, "0") || equal(value, "false") || equal(value, "FALSE") || equal(value, "False")) {
        *out = false; return true;
    }
    return false;
}

static bool lower_equal(br_slice value, const char *word)
{
    size_t i = 0;
    for (size_t at = 0; at < value.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune(part(value, at, value.len - at), &rune);
        if (!width || !word[i] || br_go_unicode_lower(rune) != (unsigned char)word[i++]) return false;
        at += width;
    }
    return !word[i];
}

static bool signed_decimal(br_slice s)
{
    uint64_t limit = INT64_MAX, number = 0;
    if (s.len && (s.data[0] == '+' || s.data[0] == '-')) {
        if (s.data[0] == '-') ++limit;
        s = part(s, 1, s.len - 1);
    }
    if (!s.len) return false;
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c < '0' || c > '9' || number > (limit - (c - '0')) / 10) return false;
        number = number * 10 + c - '0';
    }
    return true;
}

static bool duration(br_slice s)
{
    const uint64_t limit = UINT64_C(1) << 63;
    uint64_t sum = 0; bool negative = false;
    if (s.len && (s.data[0] == '+' || s.data[0] == '-')) {
        negative = s.data[0] == '-'; s = part(s, 1, s.len - 1);
    }
    if (equal(s, "0")) return true;
    if (!s.len) return false;
    while (s.len) {
        uint64_t whole = 0, fraction = 0; double scale = 1;
        size_t at = 0; bool before = false, after = false, saturated = false;
        while (at < s.len && s.data[at] >= '0' && s.data[at] <= '9') {
            if (whole > limit / 10) return false;
            whole = whole * 10 + s.data[at++] - '0';
            if (whole > limit) return false;
            before = true;
        }
        if (at < s.len && s.data[at] == '.') {
            ++at;
            while (at < s.len && s.data[at] >= '0' && s.data[at] <= '9') {
                unsigned char c = s.data[at++]; after = true;
                if (saturated) continue;
                if (fraction > INT64_MAX / 10) { saturated = true; continue; }
                uint64_t next = fraction * 10 + c - '0';
                if (next > limit) { saturated = true; continue; }
                fraction = next; scale *= 10;
            }
        }
        if (!before && !after) return false;
        size_t end = at;
        while (end < s.len && s.data[end] != '.' && !(s.data[end] >= '0' && s.data[end] <= '9')) ++end;
        br_slice name = part(s, at, end - at); uint64_t unit;
        if (equal(name, "ns")) unit = 1;
        else if (equal(name, "us") || equal(name, "\xc2\xb5s") || equal(name, "\xce\xbcs")) unit = 1000;
        else if (equal(name, "ms")) unit = 1000000;
        else if (equal(name, "s")) unit = 1000000000;
        else if (equal(name, "m")) unit = UINT64_C(60000000000);
        else if (equal(name, "h")) unit = UINT64_C(3600000000000);
        else return false;
        if (whole > limit / unit) return false;
        whole *= unit;
        if (fraction) {
            whole += (uint64_t)((double)fraction * ((double)unit / scale));
            if (whole > limit) return false;
        }
        /* Preserve the source uint64 addition, including its wrap semantics. */
        sum += whole;
        if (sum > limit) return false;
        s = part(s, end, s.len - end);
    }
    return negative || sum <= INT64_MAX;
}

static bool percent_valid(br_slice s)
{
    for (size_t i = 0; i < s.len; ++i) if (s.data[i] == '%') {
        if (s.len - i < 3) return false;
        for (size_t j = 1; j <= 2; ++j) {
            unsigned char c = s.data[i + j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        i += 2;
    }
    return true;
}

static bool split_host_port(br_slice address)
{
    size_t colon = last(address, ':'), j = 0, k = 0;
    if (colon == SIZE_MAX) return false;
    if (address.data[0] == '[') {
        size_t end = find(address, ']');
        if (end == SIZE_MAX || end + 1 != colon) return false;
        j = 1; k = end + 1;
    } else if (find(part(address, 0, colon), ':') != SIZE_MAX) return false;
    return find(part(address, j, address.len - j), '[') == SIZE_MAX &&
           find(part(address, k, address.len - k), ']') == SIZE_MAX;
}

static bool unsafe_collation(br_slice name)
{
    static const char *const names[] = {
        "big5_chinese_ci", "sjis_japanese_ci", "gbk_chinese_ci", "big5_bin", "gb2312_bin", "gbk_bin",
        "sjis_bin", "cp932_japanese_ci", "cp932_bin", "gb18030_chinese_ci", "gb18030_bin", "gb18030_unicode_520_ci"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) if (equal(name, names[i])) return true;
    return false;
}

void br_jdbc_mysql_dsn_clear(br_jdbc_mysql_dsn *out)
{
    if (!out) return;
    free(out->user.data); free(out->password.data); free(out->address.data); free(out->database.data);
    *out = (br_jdbc_mysql_dsn){0};
}

int br_jdbc_mysql_parse_dsn(br_slice dsn, br_jdbc_mysql_dsn *out, br_jdbc_dsn_status *status, char **error)
{
    if (error) *error = NULL;
    if (out) *out = (br_jdbc_mysql_dsn){0};
    if (status) *status = BR_JDBC_DSN_REJECTED;
    if (!out || !status || (!dsn.data && dsn.len)) return fail(error, "invalid JDBC MySQL DSN arguments");
    br_slice user = {0}, password = {0}, network = {0}, address = {0}, database = {0}, params = {0}, collation = {0};
    br_bytes tls = {0}, key = {0}, db = {0}, joined = {0};
    bool interpolate = false, valid = true; int rc = 0;
    size_t slash = last(dsn, '/');
    if (slash == SIZE_MAX && dsn.len) goto done;
    if (slash != SIZE_MAX) {
        if (slash) {
            br_slice left = part(dsn, 0, slash); size_t at = last(left, '@'), begin = 0;
            if (at != SIZE_MAX) {
                br_slice credentials = part(left, 0, at); size_t colon = find(credentials, ':');
                user = part(credentials, 0, colon == SIZE_MAX ? at : colon);
                if (colon != SIZE_MAX) password = part(credentials, colon + 1, at - colon - 1);
                begin = at + 1;
            }
            br_slice protocol = part(left, begin, left.len - begin); size_t open = find(protocol, '(');
            if (open != SIZE_MAX) {
                if (open + 1 >= protocol.len || protocol.data[protocol.len - 1] != ')') goto done;
                address = part(protocol, open + 1, protocol.len - open - 2);
                network = part(protocol, 0, open);
            } else network = protocol;
        }
        br_slice right = part(dsn, slash + 1, dsn.len - slash - 1); size_t question = find(right, '?');
        database = part(right, 0, question == SIZE_MAX ? right.len : question);
        if (question != SIZE_MAX) params = part(right, question + 1, right.len - question - 1);
    }
    for (size_t at = 0; at < params.len;) {
        br_slice rest = part(params, at, params.len - at); size_t amp = find(rest, '&');
        br_slice pair = part(rest, 0, amp == SIZE_MAX ? rest.len : amp);
        at += pair.len + (amp != SIZE_MAX);
        size_t equals = find(pair, '='); if (equals == SIZE_MAX) continue;
        br_slice name = part(pair, 0, equals), value = part(pair, equals + 1, pair.len - equals - 1);
        bool ignored;
        static const char *const bools[] = {"allowAllFiles", "allowCleartextPasswords", "allowFallbackToPlaintext", "allowNativePasswords", "allowOldPasswords", "checkConnLiveness", "clientFoundRows", "columnsWithAlias", "multiStatements", "parseTime", "rejectReadOnly"};
        bool is_bool = false;
        for (size_t i = 0; i < sizeof(bools) / sizeof(bools[0]); ++i) if (equal(name, bools[i])) { is_bool = true; break; }
        if (is_bool) { if (!read_bool(value, &ignored)) goto done; }
        else if (equal(name, "interpolateParams")) { if (!read_bool(value, &interpolate)) goto done; }
        else if (equal(name, "collation")) collation = value;
        else if (equal(name, "compress")) goto done;
        else if (equal(name, "strict")) { rc = fail(error, "unsupported: MySQL removed strict-mode panic boundary"); goto done; }
        else if (equal(name, "timeTruncate") || equal(name, "readTimeout") || equal(name, "timeout") || equal(name, "writeTimeout")) {
            if (!duration(value)) goto done;
        } else if (equal(name, "maxAllowedPacket")) { if (!signed_decimal(value)) goto done; }
        else if (equal(name, "loc")) {
            br_bytes location = {0};
            if (br_go_url_decode(value, true, &location, &valid, error) != 0) { free(location.data); rc = -1; goto done; }
            br_slice loc = {location.data, location.len};
            if (valid && loc.len && !equal(loc, "UTC") && !equal(loc, "Local")) {
                if (loc.data[0] == '/' || loc.data[0] == '\\' || br_slice_find(loc, LIT(".."), 0) != SIZE_MAX) valid = false;
                else rc = fail(error, "unsupported: MySQL named time-location lookup");
            }
            free(location.data);
            if (rc != 0 || !valid) goto done;
        } else if (equal(name, "tls")) {
            br_slice actual = value; bool flag;
            if (read_bool(value, &flag)) actual = flag ? LIT("true") : LIT("false");
            else if (lower_equal(value, "skip-verify")) actual = LIT("skip-verify");
            else if (lower_equal(value, "preferred")) actual = LIT("preferred");
            br_bytes next = {0};
            if (br_go_url_decode(actual, true, &next, &valid, error) != 0) { free(next.data); rc = -1; goto done; }
            free(tls.data); tls = next; if (!valid) goto done;
        } else if (equal(name, "serverPubKey")) {
            br_bytes next = {0};
            if (br_go_url_decode(value, true, &next, &valid, error) != 0) { free(next.data); rc = -1; goto done; }
            free(key.data); key = next; if (!valid) goto done;
        } else if (!percent_valid(value)) goto done;
    }
    if (br_go_url_decode(database, false, &db, &valid, error) != 0) { rc = -1; goto done; }
    if (!valid || (interpolate && unsafe_collation(collation))) goto done;
    if (!network.len) network = LIT("tcp");
    if (!address.len) {
        if (equal(network, "tcp")) address = LIT("127.0.0.1:3306");
        else if (equal(network, "unix")) address = LIT("/tmp/mysql.sock");
        else goto done;
    } else if (equal(network, "tcp") && !split_host_port(address)) {
        bool bracket = find(address, ':') != SIZE_MAX; size_t extra = bracket ? 7 : 5;
        if (address.len > SIZE_MAX - extra - 1 || !(joined.data = malloc(address.len + extra + 1))) {
            rc = fail(error, "cannot normalize MySQL DSN address"); goto done;
        }
        size_t at = 0; if (bracket) joined.data[at++] = '[';
        memcpy(joined.data + at, address.data, address.len); at += address.len;
        if (bracket) joined.data[at++] = ']';
        memcpy(joined.data + at, ":3306", 6); joined.len = address.len + extra;
        address = (br_slice){joined.data, joined.len};
    }
    br_slice tls_name = {tls.data, tls.len};
    if (tls_name.len && !equal(tls_name, "false") && !equal(tls_name, "true") &&
        !equal(tls_name, "skip-verify") && !equal(tls_name, "preferred")) goto done;
    if (key.len) goto done; /* Default source registries are empty. No key I/O. */
    if (copy(user, &out->user) != 0 || copy(password, &out->password) != 0) {
        rc = fail(error, "cannot project MySQL DSN credentials"); goto done;
    }
    if (joined.data) { out->address = joined; joined = (br_bytes){0}; }
    else if (copy(address, &out->address) != 0) { rc = fail(error, "cannot project MySQL DSN address"); goto done; }
    out->database = db; db = (br_bytes){0}; *status = BR_JDBC_DSN_ACCEPTED;
done:
    free(tls.data); free(key.data); free(db.data); free(joined.data);
    if (rc != 0 || *status != BR_JDBC_DSN_ACCEPTED) br_jdbc_mysql_dsn_clear(out);
    return rc == 0 ? 0 : -1;
}
