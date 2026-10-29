/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2 pkg/detectors/jdbc. Native drivers are not
 * linked: verification requires injected br_jdbc_sql_ops. */
#include "detectors.h"
#include "findings.h"
#include "jdbc_private.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Go/RE2 \s is space, tab, LF, FF and CR, not VT. PCRE2 \s includes VT.
 * The substitution stays inside this pattern and does not widen the class. */
/* Local ASCII class replaces Go's case-folded word class. UCP stays off. */
static const char jdbc_pattern[] =
    "(?i)jdbc:[A-Za-z0-9_]{3,10}:[^ \\t\\n\\f\\r\"'<>,{}[\\]]{10,511}"
    "[^ \\t\\n\\f\\r\"'<>,{}[\\]()&]";
static const char redact_pattern[] = "(?i)pass.*?=(.+?)\\b";

static const char *const keywords[] = {"jdbc"};
static const char description[] =
    "JDBC (Java Database Connectivity) is an API for connecting and executing queries with databases. "
    "JDBC connection strings can be used to access and manipulate databases.";

typedef struct {
    char *data;
    size_t len, cap;
} jdbc_buf;

typedef struct {
    br_jdbc_driver driver;
    br_bytes host, user, password, database, sslmode;
} jdbc_info;

typedef struct {
    const br_jdbc_state *state;
    const br_scan_ctx *ctx;
    bool verify;
    br_slice input;
    br_results *out;
    char *error;
} jdbc_scan;

static int fail(char **error, const char *message)
{
    if (error) {
        free(*error);
        *error = strdup(message);
    }
    return -1;
}

static int fail_owned(char **error, char *owned, const char *fallback)
{
    if (!owned) return fail(error, fallback);
    if (error) {
        free(*error);
        *error = owned;
    } else free(owned);
    return -1;
}

static br_slice slice_text(const char *text)
{
    return (br_slice){(const unsigned char *)text, strlen(text)};
}

static size_t find_byte(br_slice s, unsigned char c)
{
    return br_slice_find(s, (br_slice){&c, 1}, 0);
}

static size_t last_byte(br_slice s, unsigned char c)
{
    for (size_t i = s.len; i; --i)
        if (s.data && s.data[i - 1] == c) return i - 1;
    return SIZE_MAX;
}

static bool starts(br_slice s, const char *prefix)
{
    size_t n = strlen(prefix);
    return s.len >= n && s.data && !memcmp(s.data, prefix, n);
}

static bool eq_lower(br_slice key, const char *word)
{
    size_t n = strlen(word);
    if (key.len != n || (n && !key.data)) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = key.data[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        if (c != (unsigned char)word[i]) return false;
    }
    return true;
}

static bool contains_pass(br_slice key)
{
    if (key.len < 4 || !key.data) return false;
    for (size_t i = 0; i + 4 <= key.len; ++i) {
        unsigned char c0 = key.data[i], c1 = key.data[i + 1];
        unsigned char c2 = key.data[i + 2], c3 = key.data[i + 3];
        if (c0 >= 'A' && c0 <= 'Z') c0 = (unsigned char)(c0 + 32);
        if (c1 >= 'A' && c1 <= 'Z') c1 = (unsigned char)(c1 + 32);
        if (c2 >= 'A' && c2 <= 'Z') c2 = (unsigned char)(c2 + 32);
        if (c3 >= 'A' && c3 <= 'Z') c3 = (unsigned char)(c3 + 32);
        if (c0 == 'p' && c1 == 'a' && c2 == 's' && c3 == 's') return true;
    }
    return false;
}

static int copy_slice(br_slice src, br_bytes *out)
{
    unsigned char *copy = NULL;
    if (src.len) {
        if (!src.data || src.len == SIZE_MAX || !(copy = malloc(src.len + 1))) return -1;
        memcpy(copy, src.data, src.len);
        copy[src.len] = 0;
    }
    free(out->data);
    out->data = copy;
    out->len = src.len;
    return 0;
}

static int copy_text(const char *text, br_bytes *out)
{
    return copy_slice(slice_text(text), out);
}

static void info_clear(jdbc_info *info)
{
    if (!info) return;
    free(info->host.data);
    free(info->user.data);
    free(info->password.data);
    free(info->database.data);
    free(info->sslmode.data);
    *info = (jdbc_info){0};
}

static void buf_free(jdbc_buf *buf)
{
    free(buf->data);
    *buf = (jdbc_buf){0};
}

static int buf_grow(jdbc_buf *buf, size_t extra)
{
    if (extra > SIZE_MAX - buf->len - 1) return -1;
    size_t need = buf->len + extra + 1;
    if (need <= buf->cap) return 0;
    size_t cap = buf->cap ? buf->cap : 64;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) return -1;
        cap *= 2;
    }
    char *next = realloc(buf->data, cap);
    if (!next) return -1;
    buf->data = next;
    buf->cap = cap;
    return 0;
}

static int buf_add(jdbc_buf *buf, const void *data, size_t n)
{
    if (buf_grow(buf, n) != 0) return -1;
    if (n) memcpy(buf->data + buf->len, data, n);
    buf->len += n;
    buf->data[buf->len] = 0;
    return 0;
}

static int buf_stars(jdbc_buf *buf, size_t n)
{
    if (buf_grow(buf, n) != 0) return -1;
    if (n) memset(buf->data + buf->len, '*', n);
    buf->len += n;
    buf->data[buf->len] = 0;
    return 0;
}

static int buf_finish(jdbc_buf *buf, br_bytes *out)
{
    if (!buf->data && buf_add(buf, "", 0) != 0) return -1;
    out->data = (unsigned char *)buf->data;
    out->len = buf->len;
    *buf = (jdbc_buf){0};
    return 0;
}

/* Query pass wins over semicolon, last-colon and regex redactors. */
static int try_query(br_slice conn, br_bytes *out, bool *found)
{
    *out = (br_bytes){0};
    *found = false;
    size_t q = find_byte(conn, '?');
    if (q == SIZE_MAX) return 0;
    jdbc_buf buf = {0};
    bool any = false;
    if (buf_add(&buf, conn.data, q) != 0 || buf_add(&buf, "?", 1) != 0) goto oom;
    size_t at = q + 1;
    bool first = true;
    for (;;) {
        size_t end = at;
        while (end < conn.len && conn.data[end] != '&') ++end;
        br_slice param = {conn.data ? conn.data + at : NULL, end - at};
        size_t eq = find_byte(param, '=');
        br_slice key = {param.data, eq == SIZE_MAX ? param.len : eq};
        br_slice val = eq == SIZE_MAX ? (br_slice){0} : (br_slice){param.data + eq + 1, param.len - eq - 1};
        if (!first && buf_add(&buf, "&", 1) != 0) goto oom;
        first = false;
        if (contains_pass(key)) {
            if (buf_add(&buf, key.data, key.len) != 0 || buf_add(&buf, "=", 1) != 0 ||
                buf_stars(&buf, val.len) != 0) goto oom;
            any = true;
        } else if (buf_add(&buf, param.data, param.len) != 0) goto oom;
        if (end >= conn.len) break;
        at = end + 1;
    }
    if (!any) {
        buf_free(&buf);
        return 0;
    }
    *found = true;
    return buf_finish(&buf, out);
oom:
    buf_free(&buf);
    return -1;
}

static int try_odbc(br_slice conn, br_bytes *out, bool *found)
{
    *out = (br_bytes){0};
    *found = false;
    jdbc_buf buf = {0};
    bool any = false, first = true;
    size_t at = 0;
    for (;;) {
        size_t end = at;
        while (end < conn.len && conn.data[end] != ';') ++end;
        br_slice param = {conn.data ? conn.data + at : NULL, end - at};
        size_t eq = find_byte(param, '=');
        if (!first && buf_add(&buf, ";", 1) != 0) goto oom;
        first = false;
        if (eq != SIZE_MAX && contains_pass((br_slice){param.data, eq})) {
            br_slice val = {param.data + eq + 1, param.len - eq - 1};
            if (buf_add(&buf, param.data, eq + 1) != 0 || buf_stars(&buf, val.len) != 0) goto oom;
            any = true;
        } else if (buf_add(&buf, param.data, param.len) != 0) goto oom;
        if (end >= conn.len) break;
        at = end + 1;
    }
    if (!any) {
        buf_free(&buf);
        return 0;
    }
    *found = true;
    return buf_finish(&buf, out);
oom:
    buf_free(&buf);
    return -1;
}

/* Last colon before the first @, including a scheme colon when that is last. */
static int try_basic(br_slice conn, br_bytes *out, bool *found)
{
    *out = (br_bytes){0};
    *found = false;
    size_t at = find_byte(conn, '@');
    if (at == SIZE_MAX) return 0;
    br_slice user_pass = {conn.data, at};
    size_t colon = last_byte(user_pass, ':');
    if (colon == SIZE_MAX) return 0;
    jdbc_buf buf = {0};
    if (buf_add(&buf, conn.data, colon + 1) != 0 ||
        buf_stars(&buf, at - colon - 1) != 0 ||
        buf_add(&buf, conn.data + at, conn.len - at) != 0 ||
        buf_finish(&buf, out) != 0) {
        buf_free(&buf);
        return -1;
    }
    *found = true;
    return 0;
}

typedef struct {
    size_t *begin, *end;
    size_t len, cap;
    char *error;
} redact_spans;

static int collect_redact(void *user, const br_span *groups, size_t ngroups)
{
    redact_spans *spans = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end < groups[0].begin)
        return fail(&spans->error, "invalid JDBC redaction match");
    if (spans->len == spans->cap) {
        size_t cap = spans->cap ? spans->cap * 2 : 4;
        if (cap < spans->cap) return fail(&spans->error, "cannot redact JDBC connection string");
        size_t *begin = realloc(spans->begin, cap * sizeof(*begin));
        size_t *end = realloc(spans->end, cap * sizeof(*end));
        if (!begin || !end) {
            if (begin) spans->begin = begin;
            if (end) spans->end = end;
            return fail(&spans->error, "cannot redact JDBC connection string");
        }
        spans->begin = begin;
        spans->end = end;
        spans->cap = cap;
    }
    spans->begin[spans->len] = groups[0].begin;
    spans->end[spans->len] = groups[0].end;
    ++spans->len;
    return 0;
}

/* Go standard regexp counts each invalid byte as one RuneError. Shared
 * br_regex stops at those bytes, so only these two fixed patterns run on a
 * local shadow. Spans are mapped back to the original byte bounds. */
static const unsigned char jdbc_rune_error[3] = {0xef, 0xbf, 0xbd};

static bool jdbc_continuation(unsigned char c)
{
    return c >= 0x80 && c <= 0xbf;
}

static size_t jdbc_utf8_width(const unsigned char *p, size_t n)
{
    if (!n) return 0;
    unsigned char c = p[0];
    if (c < 0x80) return 1;
    if (c < 0xc2 || c > 0xf4) return 0;
    size_t need = c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
    unsigned char lo = 0x80, hi = 0xbf;
    if (c == 0xe0) lo = 0xa0;
    else if (c == 0xed) hi = 0x9f;
    else if (c == 0xf0) lo = 0x90;
    else if (c == 0xf4) hi = 0x8f;
    if (n < need || p[1] < lo || p[1] > hi) return 0;
    for (size_t i = 2; i < need; ++i)
        if (!jdbc_continuation(p[i])) return 0;
    return need;
}

typedef struct {
    unsigned char *data;
    size_t len;
    size_t *to_orig;
} jdbc_shadow;

static void shadow_free(jdbc_shadow *shadow)
{
    if (!shadow) return;
    free(shadow->data);
    free(shadow->to_orig);
    *shadow = (jdbc_shadow){0};
}

static int shadow_build(br_slice in, jdbc_shadow *out, const char *oom, char **error)
{
    *out = (jdbc_shadow){0};
    if ((!in.data && in.len) || in.len > SIZE_MAX / 3) return fail(error, oom);
    size_t cap = in.len ? in.len * 3 : 1;
    if (cap > SIZE_MAX - 1 || (cap + 1) > SIZE_MAX / sizeof(size_t)) return fail(error, oom);
    unsigned char *data = malloc(cap);
    size_t *to_orig = malloc((cap + 1) * sizeof(*to_orig));
    if (!data || !to_orig) {
        free(data);
        free(to_orig);
        return fail(error, oom);
    }
    size_t shadow_len = 0, orig = 0;
    while (in.data && orig < in.len) {
        size_t width = jdbc_utf8_width(in.data + orig, in.len - orig);
        if (!width) {
            memcpy(data + shadow_len, jdbc_rune_error, 3);
            to_orig[shadow_len] = orig;
            to_orig[shadow_len + 1] = orig;
            to_orig[shadow_len + 2] = orig;
            shadow_len += 3;
            ++orig;
        } else {
            memcpy(data + shadow_len, in.data + orig, width);
            for (size_t i = 0; i < width; ++i) to_orig[shadow_len + i] = orig + i;
            shadow_len += width;
            orig += width;
        }
    }
    to_orig[shadow_len] = orig;
    out->data = data;
    out->len = shadow_len;
    out->to_orig = to_orig;
    return 0;
}

typedef struct {
    br_match_fn fn;
    void *user;
    const size_t *to_orig;
    size_t shadow_len;
    char *error;
} jdbc_shadow_call;

static int shadow_translate(void *user, const br_span *groups, size_t ngroups)
{
    jdbc_shadow_call *call = user;
    if (!ngroups || ngroups > 4) return fail(&call->error, "invalid JDBC match");
    br_span mapped[4];
    for (size_t i = 0; i < ngroups; ++i) {
        if (groups[i].begin == SIZE_MAX && groups[i].end == SIZE_MAX) {
            mapped[i] = (br_span){SIZE_MAX, SIZE_MAX};
            continue;
        }
        if (groups[i].begin == SIZE_MAX || groups[i].end == SIZE_MAX ||
            groups[i].end < groups[i].begin || groups[i].end > call->shadow_len)
            return fail(&call->error, "invalid JDBC match");
        mapped[i].begin = call->to_orig[groups[i].begin];
        mapped[i].end = call->to_orig[groups[i].end];
        if (mapped[i].end < mapped[i].begin) return fail(&call->error, "invalid JDBC match");
    }
    return call->fn(call->user, mapped, ngroups);
}

static int regex_on_original(const br_regex *re, br_slice input, br_match_fn fn, void *user,
                             const char *oom, char **error)
{
    jdbc_shadow shadow = {0};
    if (shadow_build(input, &shadow, oom, error) != 0) return -1;
    jdbc_shadow_call call = {fn, user, shadow.to_orig, shadow.len, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(re, (br_slice){shadow.data, shadow.len}, shadow_translate, &call,
                           &regex_error);
    if (call.error) {
        free(regex_error);
        regex_error = call.error;
        rc = -1;
    }
    shadow_free(&shadow);
    if (rc) {
        if (error) *error = regex_error;
        else free(regex_error);
        return -1;
    }
    free(regex_error);
    return 0;
}

static int try_regex(const br_regex *re, br_slice conn, br_bytes *out, bool *found, char **error)
{
    *out = (br_bytes){0};
    *found = false;
    redact_spans spans = {0};
    char *regex_error = NULL;
    int rc = regex_on_original(re, conn, collect_redact, &spans,
                               "cannot redact JDBC connection string", &regex_error);
    if (spans.error) {
        free(regex_error);
        regex_error = spans.error;
        rc = -1;
    }
    if (rc) {
        free(spans.begin);
        free(spans.end);
        if (error) *error = regex_error;
        else free(regex_error);
        return -1;
    }
    free(regex_error);
    if (!spans.len) {
        free(spans.begin);
        free(spans.end);
        return 0;
    }
    jdbc_buf buf = {0};
    size_t at = 0;
    bool any = false;
    for (size_t i = 0; i < spans.len; ++i) {
        size_t begin = spans.begin[i], end = spans.end[i];
        if (begin < at || end > conn.len) {
            rc = -1;
            break;
        }
        br_slice match = {conn.data + begin, end - begin};
        size_t eq = find_byte(match, '=');
        if (buf_add(&buf, conn.data + at, begin - at) != 0) {
            rc = -1;
            break;
        }
        if (eq == SIZE_MAX) {
            if (buf_add(&buf, match.data, match.len) != 0) rc = -1;
        } else {
            if (buf_add(&buf, match.data, eq + 1) != 0 || buf_stars(&buf, match.len - eq - 1) != 0)
                rc = -1;
            any = true;
        }
        at = end;
        if (rc) break;
    }
    if (!rc && buf_add(&buf, conn.data + at, conn.len - at) != 0) rc = -1;
    free(spans.begin);
    free(spans.end);
    if (rc || !any) {
        buf_free(&buf);
        return rc ? fail(error, "cannot redact JDBC connection string") : 0;
    }
    *found = true;
    if (buf_finish(&buf, out) != 0) return fail(error, "cannot redact JDBC connection string");
    return 0;
}

static int publish_redacted(br_bytes built, char **out, char **error)
{
    if (built.len && (!built.data || memchr(built.data, 0, built.len))) {
        free(built.data);
        return fail(error, "unsupported: JDBC redacted value contains NUL");
    }
    *out = (char *)built.data;
    return 0;
}

static int redact_connection(const br_regex *re, br_slice conn, char **out, char **error)
{
    br_bytes built = {0};
    bool found = false;
    if (try_query(conn, &built, &found) != 0) return fail(error, "cannot redact JDBC connection string");
    if (found) return publish_redacted(built, out, error);
    if (try_odbc(conn, &built, &found) != 0) return fail(error, "cannot redact JDBC connection string");
    if (found) return publish_redacted(built, out, error);
    if (try_basic(conn, &built, &found) != 0) return fail(error, "cannot redact JDBC connection string");
    if (found) return publish_redacted(built, out, error);
    if (try_regex(re, conn, &built, &found, error) != 0) return -1;
    if (found) return publish_redacted(built, out, error);
    unsigned char *copy = malloc(conn.len + 1);
    if (!copy) return fail(error, "cannot redact JDBC connection string");
    if (conn.len) memcpy(copy, conn.data, conn.len);
    copy[conn.len] = 0;
    return publish_redacted((br_bytes){copy, conn.len}, out, error);
}

static int decode_field(br_slice raw, bool query, br_bytes *out, bool *valid, char **error)
{
    *valid = false;
    if (br_go_url_decode(raw, query, out, valid, error) != 0) return -1;
    if (!*valid) {
        free(out->data);
        *out = (br_bytes){0};
    }
    return 0;
}

static int put_extra(br_json *object, const char *key, br_slice value)
{
    if (!value.len) return 0;
    if (value.len > INT_MAX || !value.data) return -1;
    br_json *text = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!text) return -1;
    if (json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static int attach_extra(br_result *result, const jdbc_info *info, char **error)
{
    if (!info->host.len && !info->user.len && !info->database.len) return 0;
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return fail(error, "cannot create JDBC finding");
    if (put_extra(result->extra_data, "host", (br_slice){info->host.data, info->host.len}) != 0 ||
        put_extra(result->extra_data, "username", (br_slice){info->user.data, info->user.len}) != 0 ||
        put_extra(result->extra_data, "database", (br_slice){info->database.data, info->database.len}) != 0)
        return fail(error, "cannot create JDBC finding");
    return 0;
}

static int wrap_tcp(br_slice address, br_bytes *out)
{
    if (!address.data || address.len > SIZE_MAX - 6) return -1;
    unsigned char *copy = malloc(address.len + 6);
    if (!copy) return -1;
    memcpy(copy, "tcp(", 4);
    memcpy(copy + 4, address.data, address.len);
    copy[4 + address.len] = ')';
    copy[5 + address.len] = 0;
    out->data = copy;
    out->len = address.len + 5;
    return 0;
}

static int query_override(br_slice query, const char *key, br_bytes *dest, char **error)
{
    br_bytes value = {0};
    if (br_go_url_query_get(query, slice_text(key), &value, error) != 0) return -1;
    int rc = 0;
    if (value.len && copy_slice((br_slice){value.data, value.len}, dest) != 0)
        rc = fail(error, "cannot project JDBC connection field");
    free(value.data);
    return rc;
}

static int parse_mysql_uri(br_slice subname, jdbc_info *info, bool *ordinary, char **error)
{
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *fatal = NULL;
    int rc = br_go_url_parse(subname, &parts, &rejection, &fatal);
    if (rc) {
        br_go_url_clear(&parts);
        return fail_owned(error, fatal, "cannot parse JDBC URL");
    }
    free(fatal);
    if (rejection.kind != BR_GO_URL_OK) {
        br_go_url_clear(&parts);
        *ordinary = true; /* url.Parse error */
        return 0;
    }
    br_bytes user = {0}, password = {0}, database = {0};
    bool valid = false;
    if (!parts.has_user) {
        if (copy_text("root", &user) != 0) rc = -1;
    } else if (decode_field(parts.raw_user, false, &user, &valid, error) != 0) rc = -1;
    else if (!valid) {
        br_go_url_clear(&parts);
        free(user.data);
        *ordinary = true;
        return 0;
    }
    if (!rc && parts.has_password) {
        if (decode_field(parts.raw_password, false, &password, &valid, error) != 0) rc = -1;
        else if (!valid) {
            br_go_url_clear(&parts);
            free(user.data);
            free(password.data);
            *ordinary = true;
            return 0;
        }
    }
    if (!rc) rc = query_override(parts.raw_query, "user", &user, error);
    if (!rc) rc = query_override(parts.raw_query, "password", &password, error);
    if (!rc && decode_field(parts.raw_path, false, &database, &valid, error) != 0) rc = -1;
    else if (!rc && !valid) {
        br_go_url_clear(&parts);
        free(user.data);
        free(password.data);
        free(database.data);
        *ordinary = true;
        return 0;
    }
    br_slice path = {database.data, database.len};
    if (!rc && path.len && path.data[0] == '/') path = (br_slice){path.data + 1, path.len - 1};
    if (!rc && !path.len) {
        free(database.data);
        database = (br_bytes){0};
        if (copy_text("mysql", &database) != 0) rc = -1;
        path = (br_slice){database.data, database.len};
    }
    if (!rc && (!parts.host.len || !password.len)) {
        br_go_url_clear(&parts);
        free(user.data);
        free(password.data);
        free(database.data);
        *ordinary = true; /* missing host or password in connection string */
        return 0;
    }
    if (!rc && (wrap_tcp(parts.host, &info->host) != 0 ||
                copy_slice((br_slice){user.data, user.len}, &info->user) != 0 ||
                copy_slice((br_slice){password.data, password.len}, &info->password) != 0 ||
                copy_slice(path, &info->database) != 0))
        rc = fail(error, "cannot project JDBC connection field");
    br_go_url_clear(&parts);
    free(user.data);
    free(password.data);
    free(database.data);
    if (rc) {
        info_clear(info);
        return rc < 0 && error && *error ? -1 : fail(error, "cannot project JDBC connection field");
    }
    info->driver = BR_JDBC_MYSQL;
    return 0;
}

static int parse_mysql(br_slice subname, jdbc_info *info, bool *ordinary, char **error)
{
    if (!starts(subname, "//")) {
        *ordinary = true; /* expected host to start with // */
        return 0;
    }
    br_slice dsn = {subname.data + 2, subname.len - 2};
    br_jdbc_mysql_dsn cfg = {0};
    br_jdbc_dsn_status status = BR_JDBC_DSN_REJECTED;
    char *fatal = NULL;
    int rc = br_jdbc_mysql_parse_dsn(dsn, &cfg, &status, &fatal);
    if (rc) {
        br_jdbc_mysql_dsn_clear(&cfg);
        return fail_owned(error, fatal, "cannot parse JDBC MySQL DSN");
    }
    free(fatal);
    if (status != BR_JDBC_DSN_ACCEPTED) {
        br_jdbc_mysql_dsn_clear(&cfg);
        return parse_mysql_uri(subname, info, ordinary, error);
    }
    /* An accepted DSN with an empty address or password does not fall back. */
    if (!cfg.address.len || !cfg.password.len) {
        br_jdbc_mysql_dsn_clear(&cfg);
        *ordinary = true; /* missing host or password in connection string */
        return 0;
    }
    if (wrap_tcp((br_slice){cfg.address.data, cfg.address.len}, &info->host) != 0 ||
        copy_slice((br_slice){cfg.user.data, cfg.user.len}, &info->user) != 0 ||
        copy_slice((br_slice){cfg.password.data, cfg.password.len}, &info->password) != 0 ||
        copy_slice((br_slice){cfg.database.data, cfg.database.len}, &info->database) != 0) {
        br_jdbc_mysql_dsn_clear(&cfg);
        info_clear(info);
        return fail(error, "cannot project JDBC connection field");
    }
    br_jdbc_mysql_dsn_clear(&cfg);
    info->driver = BR_JDBC_MYSQL;
    return 0;
}

static bool sslmode_allowed(br_slice value)
{
    static const char *const allowed[] = {
        "disable", "allow", "prefer", "require", "verify-ca", "verify-full"
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
        if (value.len == strlen(allowed[i]) && value.data && !memcmp(value.data, allowed[i], value.len))
            return true;
    return false;
}

static int parse_postgres(br_slice subname, jdbc_info *info, bool *ordinary, char **error)
{
    if (!starts(subname, "//")) {
        *ordinary = true; /* expected host to start with // */
        return 0;
    }
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *fatal = NULL;
    int rc = br_go_url_parse(subname, &parts, &rejection, &fatal);
    if (rc) {
        br_go_url_clear(&parts);
        return fail_owned(error, fatal, "cannot parse JDBC URL");
    }
    free(fatal);
    if (rejection.kind != BR_GO_URL_OK) {
        br_go_url_clear(&parts);
        *ordinary = true;
        return 0;
    }
    br_bytes user = {0}, password = {0}, database = {0}, ssl = {0};
    bool valid = false;
    if (parts.has_user && decode_field(parts.raw_user, false, &user, &valid, error) != 0) rc = -1;
    else if (parts.has_user && !valid) rc = 1;
    if (!rc && parts.has_password &&
        decode_field(parts.raw_password, false, &password, &valid, error) != 0) rc = -1;
    else if (!rc && parts.has_password && !valid) rc = 1;
    if (!rc) rc = query_override(parts.raw_query, "user", &user, error);
    if (!rc) rc = query_override(parts.raw_query, "password", &password, error);
    if (!rc) {
        if (br_go_url_query_get(parts.raw_query, slice_text("sslmode"), &ssl, error) != 0) rc = -1;
        else if (!sslmode_allowed((br_slice){ssl.data, ssl.len})) {
            free(ssl.data);
            ssl = (br_bytes){0};
        }
    }
    if (!rc && decode_field(parts.raw_path, false, &database, &valid, error) != 0) rc = -1;
    else if (!rc && !valid) rc = 1;
    br_slice path = {database.data, database.len};
    if (!rc && path.len && path.data && path.data[0] == '/')
        path = (br_slice){path.data + 1, path.len - 1};
    if (!rc && !path.len) {
        free(database.data);
        database = (br_bytes){0};
        if (copy_text("postgres", &database) != 0) rc = -1;
        path = (br_slice){database.data, database.len};
    }
    if (rc > 0) {
        br_go_url_clear(&parts);
        free(user.data); free(password.data); free(database.data); free(ssl.data);
        *ordinary = true;
        return 0;
    }
    if (!rc && (!parts.host.len || !password.len)) {
        br_go_url_clear(&parts);
        free(user.data); free(password.data); free(database.data); free(ssl.data);
        *ordinary = true; /* missing host or password in connection string */
        return 0;
    }
    if (!rc && (copy_slice(parts.host, &info->host) != 0 ||
                copy_slice((br_slice){user.data, user.len}, &info->user) != 0 ||
                copy_slice((br_slice){password.data, password.len}, &info->password) != 0 ||
                copy_slice(path, &info->database) != 0 ||
                copy_slice((br_slice){ssl.data, ssl.len}, &info->sslmode) != 0))
        rc = fail(error, "cannot project JDBC connection field");
    br_go_url_clear(&parts);
    free(user.data); free(password.data); free(database.data); free(ssl.data);
    if (rc) {
        info_clear(info);
        return error && *error ? -1 : fail(error, "cannot project JDBC connection field");
    }
    info->driver = BR_JDBC_POSTGRES;
    return 0;
}

static int second_piece(br_slice value, br_slice *out)
{
    size_t colon = find_byte(value, ':');
    if (colon == SIZE_MAX) {
        *out = value;
        return 0;
    }
    size_t end = colon + 1;
    while (end < value.len && value.data[end] != ':') ++end;
    *out = (br_slice){value.data + colon + 1, end - colon - 1};
    return 1;
}

static int parse_sqlserver(br_slice subname, jdbc_info *info, bool *ordinary, char **error)
{
    if (!starts(subname, "//")) {
        *ordinary = true; /* expected connection to start with // */
        return 0;
    }
    br_slice conn = {subname.data + 2, subname.len - 2};
    br_bytes host = {0}, port = {0};
    if (copy_text("1433", &port) != 0 || copy_text("sa", &info->user) != 0 ||
        copy_text("master", &info->database) != 0) {
        free(host.data); free(port.data); info_clear(info);
        return fail(error, "cannot project JDBC connection field");
    }
    size_t at = 0, index = 0;
    int rc = 0;
    for (;;) {
        size_t end = at;
        while (end < conn.len && conn.data[end] != ';') ++end;
        br_slice param = {conn.data ? conn.data + at : NULL, end - at};
        size_t eq = find_byte(param, '=');
        if (eq == SIZE_MAX && index == 0) {
            br_slice piece = {0};
            if (second_piece(param, &piece)) {
                br_slice name = {param.data, find_byte(param, ':')};
                if (copy_slice(name, &host) != 0 || copy_slice(piece, &port) != 0) rc = -1;
            } else if (copy_slice(param, &host) != 0) rc = -1;
        } else {
            br_slice key = {param.data, eq == SIZE_MAX ? param.len : eq};
            br_slice value = eq == SIZE_MAX ? (br_slice){0} : (br_slice){param.data + eq + 1, param.len - eq - 1};
            second_piece(key, &key);
            if (eq_lower(key, "password") || eq_lower(key, "spring.datasource.password") ||
                eq_lower(key, "pwd")) {
                if (copy_slice(value, &info->password) != 0) rc = -1;
            } else if (eq_lower(key, "server")) {
                if (copy_slice(value, &host) != 0) rc = -1;
            } else if (eq_lower(key, "port")) {
                if (copy_slice(value, &port) != 0) rc = -1;
            } else if (eq_lower(key, "user") || eq_lower(key, "uid") ||
                       eq_lower(key, "user id") || eq_lower(key, "userid")) {
                if (copy_slice(value, &info->user) != 0) rc = -1;
            } else if (eq_lower(key, "database") || eq_lower(key, "databasename")) {
                if (copy_slice(value, &info->database) != 0) rc = -1;
            }
        }
        if (rc) break;
        ++index;
        if (end >= conn.len) break;
        at = end + 1;
    }
    if (!rc && (!host.len || !info->password.len)) {
        free(host.data); free(port.data); info_clear(info);
        *ordinary = true; /* missing host or password in connection string */
        return 0;
    }
    if (!rc && host.len > SIZE_MAX - port.len - 2) rc = -1;
    if (!rc) {
        unsigned char *joined = malloc(host.len + port.len + 2);
        if (!joined) rc = -1;
        else {
            if (host.len) memcpy(joined, host.data, host.len);
            joined[host.len] = ':';
            if (port.len) memcpy(joined + host.len + 1, port.data, port.len);
            info->host.data = joined;
            info->host.len = host.len + 1 + port.len;
            info->host.data[info->host.len] = 0;
        }
    }
    free(host.data);
    free(port.data);
    if (rc) {
        info_clear(info);
        return fail(error, "cannot project JDBC connection field");
    }
    info->driver = BR_JDBC_MSSQL;
    return 0;
}

static int parse_jdbc(br_slice conn, jdbc_info *info, bool *ordinary, char **error)
{
    *info = (jdbc_info){0};
    *ordinary = false;
    if (conn.len < 5 || !eq_lower((br_slice){conn.data, 5}, "jdbc:")) {
        *ordinary = true; /* expected jdbc prefix */
        return 0;
    }
    br_slice rest = {conn.data + 5, conn.len - 5};
    size_t colon = find_byte(rest, ':');
    if (colon == SIZE_MAX) {
        *ordinary = true; /* expected a colon separated subprotocol and subname */
        return 0;
    }
    br_slice proto = {rest.data, colon};
    br_slice sub = {rest.data + colon + 1, rest.len - colon - 1};
    if (eq_lower(proto, "mysql")) return parse_mysql(sub, info, ordinary, error);
    if (eq_lower(proto, "postgresql")) return parse_postgres(sub, info, ordinary, error);
    if (eq_lower(proto, "sqlserver")) return parse_sqlserver(sub, info, ordinary, error);
    *ordinary = true; /* unsupported subprotocol */
    return 0;
}

static int child_context(const br_scan_ctx *ctx, br_scan_ctx *child, char **error)
{
    *child = *ctx;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0)
        return fail(error, "cannot obtain JDBC monotonic time");
    if ((uint64_t)now.tv_sec > (uint64_t)INT64_MAX / 1000)
        return fail(error, "unsupported: JDBC monotonic time overflow");
    int64_t current = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    int64_t deadline = current > INT64_MAX - 5000 ? INT64_MAX : current + 5000;
    if (ctx->deadline_monotonic_ms && ctx->deadline_monotonic_ms < deadline)
        deadline = ctx->deadline_monotonic_ms;
    child->deadline_monotonic_ms = deadline;
    return 0;
}

static bool determinate(br_jdbc_driver driver, const br_jdbc_error *err)
{
    if (driver == BR_JDBC_MYSQL)
        return err->root == BR_JDBC_ERR_MYSQL_POINTER && err->mysql_number == 1045;
    if (driver == BR_JDBC_POSTGRES)
        return err->root == BR_JDBC_ERR_PQ_POINTER && err->pq_code.len == 5 && err->pq_code.data &&
               !memcmp(err->pq_code.data, "28P01", 5);
    if (err->as_mssql_value && err->as_mssql_value->number == 18456) {
        static const char empty_user[] = "login error: Login failed for user ''.";
        br_bytes msg = err->as_mssql_value->message;
        if (msg.len == sizeof(empty_user) - 1 && msg.data &&
            !memcmp(msg.data, empty_user, msg.len))
            return false;
        return true;
    }
    return false;
}

static int take_message(const br_jdbc_error *err, char **out, char **error)
{
    if (err->outer.len && !err->outer.data) return fail(error, "invalid JDBC SQL error");
    if (err->outer.len == SIZE_MAX) return fail(error, "invalid JDBC SQL error");
    if (err->outer.len && memchr(err->outer.data, 0, err->outer.len))
        return fail(error, "unsupported: JDBC SQL error contains NUL");
    char *text = malloc(err->outer.len + 1);
    if (!text) return fail(error, "cannot copy JDBC SQL error");
    if (err->outer.len) memcpy(text, err->outer.data, err->outer.len);
    text[err->outer.len] = 0;
    *out = text;
    return 0;
}

enum { JDBC_SUCCESS = 0, JDBC_DETERMINATE = 1, JDBC_INDETERMINATE = 2 };

static int classify(br_jdbc_driver driver, const br_jdbc_error *err, int *verdict,
                    char **message, char **error)
{
    *message = NULL;
    if (err->root == BR_JDBC_ERR_NONE) {
        *verdict = JDBC_SUCCESS;
        return 0;
    }
    if (determinate(driver, err)) {
        *verdict = JDBC_DETERMINATE;
        return 0;
    }
    if (take_message(err, message, error) != 0) return -1;
    *verdict = JDBC_INDETERMINATE;
    return 0;
}

static int attempt(const br_jdbc_sql_ops *ops, void *user, br_jdbc_driver driver, br_slice dsn,
                   const br_scan_ctx *child, int *verdict, char **message, char **error)
{
    void *db = NULL;
    br_jdbc_error ordinary = {0};
    char *fatal = NULL;
    if (!ops || !ops->open || !ops->ping || !ops->close)
        return fail(error, "unsupported: JDBC verification without injected SQL ops");
    int open_rc = ops->open(user, driver, dsn, &db, &ordinary, &fatal);
    if (open_rc) {
        br_jdbc_error_clear(&ordinary);
        return fail_owned(error, fatal, "unsupported: JDBC SQL open failed");
    }
    free(fatal);
    fatal = NULL;
    if (ordinary.root != BR_JDBC_ERR_NONE) {
        int rc = classify(driver, &ordinary, verdict, message, error);
        br_jdbc_error_clear(&ordinary);
        return rc;
    }
    br_jdbc_error_clear(&ordinary);
    if (!db) return fail(error, "unsupported: JDBC SQL open published no handle");

    ordinary = (br_jdbc_error){0};
    fatal = NULL;
    int ping_rc = ops->ping(user, db, child, &ordinary, &fatal);
    char *first = NULL;
    if (ping_rc) {
        first = fatal ? fatal : strdup("unsupported: JDBC SQL ping failed");
        fatal = NULL;
    } else free(fatal);
    br_jdbc_error close_err = {0};
    char *close_diag = NULL;
    int close_rc = ops->close(user, db, &close_err, &close_diag);
    br_jdbc_error_clear(&close_err); /* Ordinary close errors are ignored. */
    if (close_rc && !ping_rc) {
        first = close_diag ? close_diag : strdup("unsupported: JDBC SQL close failed");
        close_diag = NULL;
    }
    free(close_diag);
    if (ping_rc || close_rc) {
        br_jdbc_error_clear(&ordinary);
        if (!first) return fail(error, "cannot copy JDBC SQL error");
        return fail_owned(error, first, ping_rc ? "unsupported: JDBC SQL ping failed"
                                                 : "unsupported: JDBC SQL close failed");
    }
    free(first);
    int rc = classify(driver, &ordinary, verdict, message, error);
    br_jdbc_error_clear(&ordinary);
    return rc;
}

static int add_kv(jdbc_buf *buf, bool *first, const char *key, br_slice value)
{
    if (!value.len) return 0;
    if ((!*first && buf_add(buf, " ", 1) != 0) || buf_add(buf, key, strlen(key)) != 0 ||
        buf_add(buf, "=", 1) != 0 || buf_add(buf, value.data, value.len) != 0)
        return -1;
    *first = false;
    return 0;
}

/* Field order is local and stable. Go map order inside the built string is not. */
static int build_postgres(const jdbc_info *info, bool include_db, br_bytes *out)
{
    br_slice host = {info->host.data, info->host.len}, port = {0};
    size_t colon = find_byte(host, ':');
    if (colon != SIZE_MAX) {
        port = (br_slice){host.data + colon + 1, host.len - colon - 1};
        host.len = colon;
    }
    jdbc_buf buf = {0};
    bool first = true;
    br_slice user = info->user.len ? (br_slice){info->user.data, info->user.len} : slice_text("postgres");
    if (add_kv(&buf, &first, "user", user) != 0 ||
        add_kv(&buf, &first, "password", (br_slice){info->password.data, info->password.len}) != 0 ||
        add_kv(&buf, &first, "host", host) != 0 ||
        add_kv(&buf, &first, "port", port) != 0 ||
        add_kv(&buf, &first, "connect_timeout", slice_text("5")) != 0 ||
        add_kv(&buf, &first, "sslmode", (br_slice){info->sslmode.data, info->sslmode.len}) != 0)
        goto oom;
    if ((include_db && add_kv(&buf, &first, "dbname", slice_text("postgres")) != 0) ||
        buf_finish(&buf, out) != 0) goto oom;
    return 0;
oom:
    buf_free(&buf);
    return -1;
}

static int build_mysql(const jdbc_info *info, br_bytes *out)
{
    jdbc_buf buf = {0};
    bool cred = info->user.len || info->password.len;
    if (cred) {
        if (buf_add(&buf, info->user.data, info->user.len) != 0) goto oom;
        if (info->password.len &&
            (buf_add(&buf, ":", 1) != 0 || buf_add(&buf, info->password.data, info->password.len) != 0))
            goto oom;
        if (buf_add(&buf, "@", 1) != 0) goto oom;
    }
    if (buf_add(&buf, info->host.data, info->host.len) != 0 || buf_add(&buf, "/", 1) != 0 ||
        buf_add(&buf, "?timeout=5s", sizeof("?timeout=5s") - 1) != 0 || buf_finish(&buf, out) != 0)
        goto oom;
    return 0;
oom:
    buf_free(&buf);
    return -1;
}

static int build_sqlserver(const jdbc_info *info, br_bytes *out)
{
    jdbc_buf buf = {0};
    if (buf_add(&buf, "sqlserver://", 12) != 0 ||
        buf_add(&buf, info->user.data, info->user.len) != 0 || buf_add(&buf, ":", 1) != 0 ||
        buf_add(&buf, info->password.data, info->password.len) != 0 || buf_add(&buf, "@", 1) != 0 ||
        buf_add(&buf, info->host.data, info->host.len) != 0 ||
        buf_add(&buf, "?database=master&connection+timeout=5",
                sizeof("?database=master&connection+timeout=5") - 1) != 0 ||
        buf_finish(&buf, out) != 0) {
        buf_free(&buf);
        return -1;
    }
    return 0;
}

static int join_messages(char **messages, size_t n, char **out, char **error)
{
    if (n == 1) {
        *out = messages[0];
        messages[0] = NULL;
        return 0;
    }
    size_t len = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t part = strlen(messages[i]);
        if (len > SIZE_MAX - part - (i + 1 < n)) return fail(error, "cannot join JDBC verification errors");
        len += part + (i + 1 < n);
    }
    char *joined = malloc(len + 1);
    if (!joined) return fail(error, "cannot join JDBC verification errors");
    size_t at = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t part = strlen(messages[i]);
        memcpy(joined + at, messages[i], part);
        at += part;
        if (i + 1 < n) joined[at++] = '\n';
    }
    joined[at] = 0;
    *out = joined;
    return 0;
}

static int verify_info(const br_jdbc_state *state, const br_scan_ctx *ctx, br_slice secret,
                       const jdbc_info *info, br_result *result, char **error)
{
    br_scan_ctx child;
    if (child_context(ctx, &child, error) != 0) return -1;
    br_bytes built[2] = {0};
    size_t nbuilt = 0;
    int rc = 0;
    if (info->driver == BR_JDBC_MYSQL) rc = build_mysql(info, &built[nbuilt++]);
    else if (info->driver == BR_JDBC_POSTGRES) {
        /* Source tries dbname postgres, then omits it. The parsed database is not used. */
        if (!rc) rc = build_postgres(info, true, &built[nbuilt++]);
        if (!rc) rc = build_postgres(info, false, &built[nbuilt++]);
    } else rc = build_sqlserver(info, &built[nbuilt++]);
    if (rc) {
        for (size_t i = 0; i < nbuilt; ++i) free(built[i].data);
        return fail(error, "cannot build JDBC verification candidate");
    }
    char *messages[2] = {0};
    size_t nmessages = 0;
    int verdict = JDBC_INDETERMINATE;
    for (size_t i = 0; i < nbuilt; ++i) {
        char *message = NULL;
        rc = attempt(state->sql, state->sql_user, info->driver,
                     (br_slice){built[i].data, built[i].len}, &child, &verdict, &message, error);
        if (rc) break;
        if (verdict == JDBC_SUCCESS || verdict == JDBC_DETERMINATE) {
            free(message);
            break;
        }
        messages[nmessages++] = message;
    }
    for (size_t i = 0; i < nbuilt; ++i) free(built[i].data);
    if (rc) {
        for (size_t i = 0; i < nmessages; ++i) free(messages[i]);
        return -1;
    }
    if (verdict == JDBC_SUCCESS) {
        for (size_t i = 0; i < nmessages; ++i) free(messages[i]);
        result->verified = true;
        return 0;
    }
    if (verdict == JDBC_DETERMINATE) {
        for (size_t i = 0; i < nmessages; ++i) free(messages[i]);
        return 0;
    }
    char *joined = NULL;
    rc = join_messages(messages, nmessages, &joined, error);
    for (size_t i = 0; i < nmessages; ++i) free(messages[i]);
    if (rc) return -1;
    rc = br_result_set_verification_error(result, joined, &secret, 1);
    free(joined);
    return rc == 0 ? 0 : fail(error, "cannot set JDBC verification error");
}

static void rollback(br_results *out, size_t before)
{
    if (!out) return;
    while (out->len > before) {
        br_result_clear(&out->items[out->len - 1]);
        --out->len;
    }
}

static int on_match(void *user, const br_span *groups, size_t ngroups)
{
    jdbc_scan *scan = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end < groups[0].begin ||
        groups[0].end > scan->input.len)
        return fail(&scan->error, "invalid JDBC match");
    br_slice match = {scan->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    char *redacted = NULL;
    if (redact_connection(scan->state->redact, match, &redacted, &scan->error) != 0) return -1;
    br_result result = {0};
    if (br_finding_key_bytes(&result, 10, match, "connection_string") != 0) {
        free(redacted);
        return fail(&scan->error, "cannot create JDBC finding");
    }
    result.redacted = redacted;
    jdbc_info info = {0};
    bool ordinary = false;
    if (parse_jdbc(match, &info, &ordinary, &scan->error) != 0) {
        info_clear(&info);
        br_result_clear(&result);
        return -1;
    }
    if (ordinary) {
        info_clear(&info);
        if (scan->verify) {
            br_result_clear(&result);
            return 0; /* Parse failure plus verify drops the candidate. No setter. */
        }
    } else if (attach_extra(&result, &info, &scan->error) != 0 ||
               (scan->verify && verify_info(scan->state, scan->ctx, match, &info, &result,
                                            &scan->error) != 0)) {
        info_clear(&info);
        br_result_clear(&result);
        return -1;
    }
    info_clear(&info);
    if (br_results_push(scan->out, &result) != 0) {
        br_result_clear(&result);
        return fail(&scan->error, "cannot append JDBC finding");
    }
    return 0;
}

static int scan_jdbc(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    /* AddLogger type-asserts, then calls parent.Value, before extraction. */
    if (!ctx) return fail(error, "unsupported upstream panic: JDBC nil context");
    if (!detector || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized JDBC scan");
    const br_jdbc_state *state = detector->state;
    if (!state || !state->regex || !state->redact)
        return fail(error, "invalid or uninitialized JDBC scan");
    size_t before = out->len;
    jdbc_scan scan = {state, ctx, verify, input, out, NULL};
    char *regex_error = NULL;
    int rc = regex_on_original(state->regex, input, on_match, &scan,
                               "cannot scan JDBC connection string", &regex_error);
    if (scan.error) {
        free(regex_error);
        regex_error = scan.error;
        rc = -1;
    }
    if (rc) {
        rollback(out, before);
        if (error) *error = regex_error;
        else free(regex_error);
        return -1;
    }
    free(regex_error);
    return 0;
}

static bool jdbc_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static br_jdbc_state state;
static const br_detector detector = {
    .type = 10, .version = 0, .name = "JDBC", .custom_name = "", .description = description,
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &state, .scan = scan_jdbc, .false_positive = jdbc_false_positive,
};

int br_jdbc_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out) return fail(error, "invalid JDBC detector output");
    if (!state.regex && br_regex_compile(jdbc_pattern, &state.regex, error) != 0) return -1;
    if (!state.redact && br_regex_compile(redact_pattern, &state.redact, error) != 0) return -1;
    state.sql = NULL;
    state.sql_user = NULL;
    *out = &detector;
    return 0;
}
