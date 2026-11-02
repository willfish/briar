/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/postgres/postgres.go.
 * Verification never dials. A NULL SQL hook is an indeterminate error.
 * An injected hook classifies pq/pgx outcomes without SQL, DNS, or a socket.
 * Verify connection strings sort keys; Go map order is intentionally unstable. */
#include "detectors.h"
#include "findings.h"
#include "../go_url.h"

#include <arpa/inet.h>
#include <json-c/json.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { char *key, *value; } pg_param;
typedef struct { pg_param *items; size_t len, cap; } pg_params;
typedef struct { char *uri, *scheme; } pg_hit;
typedef struct { pg_hit *items; size_t len, cap; } pg_hits;

typedef struct {
    bool ok;
    bool ssl_not_supported;
    const char *message;
    const char *pg_code;
} br_postgres_sql_outcome;

typedef int (*br_postgres_sql_fn)(void *, bool neon, const char *conninfo,
                                  br_postgres_sql_outcome *, char **error);

static br_regex *uri_re, *part_re;
static br_regex **ignores;
static size_t nignores;
static bool detect_loopback;
static br_postgres_sql_fn sql_hook;
static void *sql_user;

int br_postgres_set_detect_loopback(bool enabled)
{
    detect_loopback = enabled;
    return 0;
}

int br_postgres_set_sql_hook(br_postgres_sql_fn fn, void *user)
{
    sql_hook = fn;
    sql_user = user;
    return 0;
}

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

int br_postgres_set_ignore_patterns(const char *const *patterns, size_t count, char **error)
{
    if (error) *error = NULL;
    if (count && !patterns) return fail(error, "invalid Postgres ignore patterns");
    if (count > SIZE_MAX / sizeof(br_regex *)) return fail(error, "too many Postgres ignore patterns");
    br_regex **next = count ? calloc(count, sizeof(*next)) : NULL;
    if (count && !next) return fail(error, "cannot allocate Postgres ignore patterns");
    for (size_t i = 0; i < count; ++i) {
        if (br_regex_compile(patterns[i], &next[i], error) != 0) {
            for (size_t j = 0; j < i; ++j) br_regex_free(next[j]);
            free(next);
            if (error && !*error) fail(error, "invalid Postgres ignore pattern");
            return -1;
        }
    }
    for (size_t i = 0; i < nignores; ++i) br_regex_free(ignores[i]);
    free(ignores);
    ignores = next;
    nignores = count;
    return 0;
}

static void params_clear(pg_params *params)
{
    if (!params) return;
    for (size_t i = 0; i < params->len; ++i) {
        free(params->items[i].key);
        free(params->items[i].value);
    }
    free(params->items);
    *params = (pg_params){0};
}

static char *dup_len(const char *text, size_t len)
{
    if (len == SIZE_MAX) return NULL;
    char *copy = malloc(len + 1);
    if (!copy) return NULL;
    if (len) memcpy(copy, text, len);
    copy[len] = '\0';
    return copy;
}

static int params_set(pg_params *params, const char *key, const char *value, char **error)
{
    for (size_t i = 0; i < params->len; ++i) {
        if (strcmp(params->items[i].key, key)) continue;
        char *copy = dup_len(value, strlen(value));
        if (!copy) return fail(error, "cannot store Postgres parameter");
        free(params->items[i].value);
        params->items[i].value = copy;
        return 0;
    }
    if (params->len == params->cap) {
        if (params->cap > SIZE_MAX / sizeof(*params->items) / 2) return fail(error, "too many Postgres parameters");
        size_t cap = params->cap ? params->cap * 2 : 8;
        pg_param *items = realloc(params->items, cap * sizeof(*items));
        if (!items) return fail(error, "cannot store Postgres parameter");
        params->items = items;
        params->cap = cap;
    }
    char *owned_key = dup_len(key, strlen(key));
    char *owned_value = dup_len(value, strlen(value));
    if (!owned_key || !owned_value) {
        free(owned_key);
        free(owned_value);
        return fail(error, "cannot store Postgres parameter");
    }
    params->items[params->len++] = (pg_param){owned_key, owned_value};
    return 0;
}

static const char *params_get(const pg_params *params, const char *key)
{
    for (size_t i = 0; i < params->len; ++i)
        if (!strcmp(params->items[i].key, key)) return params->items[i].value;
    return NULL;
}

static void params_del(pg_params *params, const char *key)
{
    for (size_t i = 0; i < params->len; ++i) {
        if (strcmp(params->items[i].key, key)) continue;
        free(params->items[i].key);
        free(params->items[i].value);
        params->items[i] = params->items[--params->len];
        return;
    }
}

static int params_copy(const pg_params *src, pg_params *dst, char **error)
{
    *dst = (pg_params){0};
    for (size_t i = 0; i < src->len; ++i)
        if (params_set(dst, src->items[i].key, src->items[i].value, error)) {
            params_clear(dst);
            return -1;
        }
    return 0;
}

static void params_sort(pg_params *params)
{
    for (size_t i = 1; i < params->len; ++i) {
        pg_param item = params->items[i];
        size_t j = i;
        while (j && strcmp(params->items[j - 1].key, item.key) > 0) {
            params->items[j] = params->items[j - 1];
            --j;
        }
        params->items[j] = item;
    }
}

static int64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool is_done(const br_scan_ctx *ctx, char **error)
{
    if (ctx->cancelled && ctx->cancelled(ctx->cancel_user)) return true;
    if (!ctx->deadline_monotonic_ms) return false;
    int64_t now = now_ms();
    if (now < 0) {
        fail(error, "monotonic clock unavailable");
        return true;
    }
    return now >= ctx->deadline_monotonic_ms;
}

static bool loopback_host(const char *host)
{
    if (!strcmp(host, "localhost")) return true;
    unsigned char ip[16];
    if (inet_pton(AF_INET, host, ip) == 1) return ip[0] == 127;
    if (inet_pton(AF_INET6, host, ip) == 1) {
        static const unsigned char loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        return !memcmp(ip, loop, 16) || (!memcmp(ip, mapped, 12) && ip[12] == 127);
    }
    return false;
}

static bool neon_host(const char *host)
{
    static const char suffix[] = ".neon.tech";
    size_t n = strlen(host), tail = sizeof(suffix) - 1;
    if (n < tail) return false;
    for (size_t i = 0; i < tail; ++i) {
        unsigned char c = (unsigned char)host[n - tail + i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        if (c != (unsigned char)suffix[i]) return false;
    }
    return true;
}

static int mark_match(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups;
    (void)ngroups;
    *(bool *)user = true;
    return 0;
}

static int should_ignore(br_slice uri, bool *skip, char **error)
{
    *skip = false;
    for (size_t i = 0; i < nignores; ++i) {
        bool matched = false;
        if (br_regex_each(ignores[i], uri, mark_match, &matched, error) != 0) return -1;
        if (matched) {
            *skip = true;
            return 0;
        }
    }
    return 0;
}

static int decode_text(br_slice raw, bool query, char **out, bool *valid, char **error)
{
    *out = NULL;
    *valid = true;
    if (!raw.len) {
        *out = dup_len("", 0);
        return *out ? 0 : fail(error, "cannot decode Postgres URL");
    }
    br_bytes decoded = {0};
    if (br_go_url_decode(raw, query, &decoded, valid, error) != 0) return -1;
    if (!*valid) {
        free(decoded.data);
        return 0;
    }
    *out = dup_len(decoded.data ? (const char *)decoded.data : "", decoded.len);
    free(decoded.data);
    return *out ? 0 : fail(error, "cannot decode Postgres URL");
}

static int escape_value(const char *value, char **out, char **error)
{
    size_t n = strlen(value), extra = 0;
    for (size_t i = 0; i < n; ++i)
        if (value[i] == '\'' || value[i] == '\\') ++extra;
    if (n == SIZE_MAX || extra > SIZE_MAX - n - 1) return fail(error, "Postgres parameter is too large");
    char *copy = malloc(n + extra + 1);
    if (!copy) return fail(error, "cannot escape Postgres parameter");
    size_t at = 0;
    for (size_t i = 0; i < n; ++i) {
        if (value[i] == '\'' || value[i] == '\\') copy[at++] = '\\';
        copy[at++] = value[i];
    }
    copy[at] = '\0';
    *out = copy;
    return 0;
}

static int push_kv(char ***kvs, size_t *n, size_t *cap, const char *key, const char *value, char **error)
{
    if (!value || !*value) return 0;
    char *escaped = NULL;
    if (escape_value(value, &escaped, error) != 0) return -1;
    size_t key_len = strlen(key), value_len = strlen(escaped);
    if (key_len > SIZE_MAX - 4 || value_len > SIZE_MAX - 4 - key_len) {
        free(escaped); return fail(error, "Postgres connection parameter is too large");
    }
    size_t need = key_len + 3 + value_len;
    char *item = malloc(need + 1);
    if (!item) {
        free(escaped);
        return fail(error, "cannot format Postgres connection parameter");
    }
    snprintf(item, need + 1, "%s='%s'", key, escaped);
    free(escaped);
    if (*n == *cap) {
        if (*cap > SIZE_MAX / sizeof(**kvs) / 2) {
            free(item); return fail(error, "too many Postgres connection parameters");
        }
        size_t next = *cap ? *cap * 2 : 8;
        char **grown = realloc(*kvs, next * sizeof(*grown));
        if (!grown) {
            free(item);
            return fail(error, "cannot format Postgres connection parameter");
        }
        *kvs = grown;
        *cap = next;
    }
    (*kvs)[(*n)++] = item;
    return 0;
}

static bool optional_port(const char *suffix)
{
    if (!suffix || suffix[0] != ':') return false;
    for (const char *p = suffix + 1; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    return true;
}

static int split_host_port(const char *hostport, char **host, char **port, char **error)
{
    *host = NULL;
    *port = NULL;
    const char *colon = strrchr(hostport, ':');
    const char *host_end = hostport + strlen(hostport);
    if (colon && optional_port(colon)) {
        host_end = colon;
        *port = dup_len(colon + 1, strlen(colon + 1));
        if (!*port) return fail(error, "cannot copy Postgres host");
    }
    const char *host_begin = hostport;
    if (host_end > host_begin && host_begin[0] == '[' && host_end[-1] == ']') {
        ++host_begin;
        --host_end;
    }
    *host = dup_len(host_begin, (size_t)(host_end - host_begin));
    if (!*host) return fail(error, "cannot copy Postgres host");
    return 0;
}

static int add_query(char ***kvs, size_t *n, size_t *cap, br_slice query, char **error)
{
    size_t at = 0;
    while (at < query.len) {
        size_t end = at;
        while (end < query.len && query.data[end] != '&') ++end;
        br_slice pair = {query.data + at, end - at};
        at = end < query.len ? end + 1 : end;
        bool semi = false;
        for (size_t i = 0; i < pair.len; ++i) semi |= pair.data[i] == ';';
        if (!pair.len || semi) continue;
        size_t eq = SIZE_MAX;
        for (size_t i = 0; i < pair.len; ++i)
            if (pair.data[i] == '=') { eq = i; break; }
        br_slice raw_key = eq == SIZE_MAX ? pair : (br_slice){pair.data, eq};
        br_slice raw_value = eq == SIZE_MAX ? (br_slice){0} : (br_slice){pair.data + eq + 1, pair.len - eq - 1};
        char *key = NULL, *value = NULL;
        bool valid = false;
        if (decode_text(raw_key, true, &key, &valid, error) != 0) return -1;
        if (!valid || !key || !*key) {
            free(key);
            continue;
        }
        if (decode_text(raw_value, true, &value, &valid, error) != 0) {
            free(key);
            return -1;
        }
        bool seen = false;
        if (valid && value) {
            char prefix[256];
            snprintf(prefix, sizeof(prefix), "%s='", key);
            for (size_t i = 0; i < *n; ++i)
                if (!strncmp((*kvs)[i], prefix, strlen(prefix))) seen = true;
        }
        if (valid && value && *value && !seen && push_kv(kvs, n, cap, key, value, error) != 0) {
            free(key);
            free(value);
            return -1;
        }
        free(key);
        free(value);
    }
    return 0;
}

typedef struct {
    pg_params *params;
    const char *text;
    char *error;
} part_box;

static int take_part(void *user, const br_span *groups, size_t ngroups)
{
    part_box *box = user;
    if (ngroups < 3 || groups[1].begin == SIZE_MAX || groups[2].begin == SIZE_MAX ||
        groups[1].end < groups[1].begin || groups[2].end < groups[2].begin ||
        groups[2].end > strlen(box->text))
        return fail(&box->error, "invalid Postgres connection parameter");
    char *key = dup_len(box->text + groups[1].begin, groups[1].end - groups[1].begin);
    char *value = dup_len(box->text + groups[2].begin, groups[2].end - groups[2].begin);
    if (!key || !value) {
        free(key);
        free(value);
        return fail(&box->error, "cannot store Postgres parameter");
    }
    int rc = params_set(box->params, key, value, &box->error);
    free(key);
    free(value);
    return rc;
}

static int parse_uri(const char *uri, const char *scheme, pg_params *params, char **error)
{
    *params = (pg_params){0};
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    br_slice input = {(const unsigned char *)uri, strlen(uri)};
    if (br_go_url_parse(input, &parts, &rejection, error) != 0) return -1;
    if (rejection.kind != BR_GO_URL_OK) {
        br_go_url_clear(&parts);
        return 1; /* Ordinary ParseURL rejection. */
    }
    char **kvs = NULL;
    size_t n = 0, cap = 0;
    int rc = 0;
    char *user = NULL, *password = NULL, *path = NULL, *host = NULL, *port = NULL;
    bool valid = true;
    if (parts.has_user && decode_text(parts.raw_user, false, &user, &valid, error) != 0) rc = -1;
    if (!rc && !valid) rc = 1;
    if (!rc && parts.has_password && decode_text(parts.raw_password, false, &password, &valid, error) != 0) rc = -1;
    if (!rc && !valid) rc = 1;
    if (!rc && parts.raw_path.len > 1) {
        br_slice rest = {parts.raw_path.data + 1, parts.raw_path.len - 1};
        if (decode_text(rest, false, &path, &valid, error) != 0) rc = -1;
        if (!rc && !valid) rc = 1;
    }
    if (!rc && parts.host.len) {
        char *hostport = dup_len((const char *)parts.host.data, parts.host.len);
        if (!hostport) rc = fail(error, "cannot copy Postgres host");
        else rc = split_host_port(hostport, &host, &port, error);
        free(hostport);
    }
    if (!rc) rc = push_kv(&kvs, &n, &cap, "user", user, error);
    if (!rc) rc = push_kv(&kvs, &n, &cap, "password", password, error);
    if (!rc) rc = push_kv(&kvs, &n, &cap, "host", host, error);
    if (!rc) rc = push_kv(&kvs, &n, &cap, "port", port, error);
    if (!rc) rc = push_kv(&kvs, &n, &cap, "dbname", path, error);
    if (!rc) rc = add_query(&kvs, &n, &cap, parts.raw_query, error);
    size_t joined_len = 0;
    for (size_t i = 0; !rc && i < n; ++i) {
        size_t len = strlen(kvs[i]), sep = i ? 1 : 0;
        if (joined_len > SIZE_MAX - sep - 1 || len > SIZE_MAX - sep - 1 - joined_len)
            rc = fail(error, "Postgres connection string is too large");
        else joined_len += len + sep;
    }
    char *joined = rc ? NULL : calloc(joined_len + 1, 1);
    if (!rc && !joined) rc = fail(error, "cannot join Postgres connection string");
    if (!rc) {
        for (size_t i = 1; i < n; ++i) {
            char *item = kvs[i];
            size_t j = i;
            while (j && strcmp(kvs[j - 1], item) > 0) {
                kvs[j] = kvs[j - 1];
                --j;
            }
            kvs[j] = item;
        }
        size_t at = 0;
        for (size_t i = 0; i < n; ++i) {
            if (i) joined[at++] = ' ';
            size_t len = strlen(kvs[i]);
            memcpy(joined + at, kvs[i], len);
            at += len;
        }
        part_box box = {params, joined, NULL};
        if (joined_len && br_regex_each(part_re, (br_slice){(const unsigned char *)joined, joined_len},
                                        take_part, &box, error) != 0)
            rc = -1;
        if (!rc && box.error) {
            if (error && !*error) *error = box.error;
            else free(box.error);
            rc = -1;
        }
    }
    if (!rc && params_set(params, "db_type", scheme, error) != 0) rc = -1;
    for (size_t i = 0; i < n; ++i) free(kvs[i]);
    free(kvs);
    free(joined);
    free(user);
    free(password);
    free(path);
    free(host);
    free(port);
    br_go_url_clear(&parts);
    if (rc < 0) params_clear(params);
    return rc < 0 ? -1 : rc;
}

static int format_conninfo(const pg_params *params, bool pgx, char **out, char **error)
{
    pg_params copy = {0};
    if (params_copy(params, &copy, error) != 0) return -1;
    params_sort(&copy);
    size_t total = 1;
    for (size_t i = 0; i < copy.len; ++i) {
        if (!strcmp(copy.items[i].key, "db_type")) continue;
        if (pgx && !strcmp(copy.items[i].key, "requiressl")) continue;
        size_t kn = strlen(copy.items[i].key), vn = strlen(copy.items[i].value);
        if (total > SIZE_MAX - 3 || kn > SIZE_MAX - 3 - total || vn > SIZE_MAX - 3 - total - kn) {
            params_clear(&copy); return fail(error, "Postgres connection string is too large");
        }
        total += kn + 3 + vn;
    }
    char *text = malloc(total);
    if (!text) {
        params_clear(&copy);
        return fail(error, "cannot format Postgres connection string");
    }
    size_t at = 0;
    for (size_t i = 0; i < copy.len; ++i) {
        if (!strcmp(copy.items[i].key, "db_type")) continue;
        if (pgx && !strcmp(copy.items[i].key, "requiressl")) continue;
        size_t kn = strlen(copy.items[i].key), vn = strlen(copy.items[i].value);
        if (at + kn + 3 + vn >= total) {
            free(text);
            params_clear(&copy);
            return fail(error, "cannot format Postgres connection string");
        }
        memcpy(text + at, copy.items[i].key, kn);
        at += kn;
        text[at++] = '=';
        text[at++] = '\'';
        memcpy(text + at, copy.items[i].value, vn);
        at += vn;
        text[at++] = '\'';
        text[at] = '\0';
    }
    params_clear(&copy);
    *out = text;
    return 0;
}

static bool database_missing(const char *message, const char *dbname)
{
    const char *name = dbname && *dbname ? dbname : "postgres";
    char expected[192];
    snprintf(expected, sizeof(expected), "database \"%s\" does not exist", name);
    return message && strstr(message, expected) != NULL;
}

static void classify(const br_postgres_sql_outcome *outcome, const char *dbname,
                     bool *verified, const char **cause)
{
    *verified = false;
    *cause = NULL;
    if (!outcome) return;
    if (outcome->ok) {
        *verified = true;
        return;
    }
    if (outcome->pg_code && !strcmp(outcome->pg_code, "28P01")) return;
    if (outcome->pg_code && !strcmp(outcome->pg_code, "3D000")) {
        *verified = true;
        return;
    }
    if (outcome->message && strstr(outcome->message, "password authentication failed")) return;
    if (database_missing(outcome->message, dbname)) {
        *verified = true;
        return;
    }
    *cause = outcome->message;
}

static int verify_params(const br_scan_ctx *ctx, pg_params *params, br_result *result, char **error)
{
    (void)ctx;
    const char *password = params_get(params, "password");
    const char *host = params_get(params, "host");
    bool neon = host && neon_host(host);
    pg_params attempt = {0};
    if (params_copy(params, &attempt, error) != 0) return -1;
    if (!neon) {
        const char *sslmode = params_get(&attempt, "sslmode");
        if (sslmode && (!strcmp(sslmode, "allow") || !strcmp(sslmode, "prefer")))
            params_del(&attempt, "sslmode");
        params_del(&attempt, "db_type");
    }
    char *conninfo = NULL;
    int rc = format_conninfo(&attempt, neon, &conninfo, error);
    br_postgres_sql_outcome outcome = {0};
    if (!rc && sql_hook) {
        rc = sql_hook(sql_user, neon, conninfo, &outcome, error);
        if (!rc && !neon && outcome.ssl_not_supported && !params_get(&attempt, "sslmode")) {
            if (params_set(&attempt, "sslmode", "disable", error) != 0) rc = -1;
            else {
                free(conninfo);
                conninfo = NULL;
                outcome = (br_postgres_sql_outcome){0};
                if (format_conninfo(&attempt, false, &conninfo, error) != 0 ||
                    sql_hook(sql_user, false, conninfo, &outcome, error) != 0)
                    rc = -1;
            }
        }
    }
    bool verified = false;
    const char *cause = NULL;
    if (!rc && sql_hook) classify(&outcome, params_get(params, "dbname"), &verified, &cause);
    if (!rc && !sql_hook)
        cause = neon ? "unsupported: Postgres pgx verification" : "unsupported: Postgres SQL verification";
    if (!rc) {
        result->verified = verified;
        br_slice secret = {(const unsigned char *)password, password ? strlen(password) : 0};
        if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
            rc = fail(error, "cannot set Postgres verification error");
    }
    free(conninfo);
    params_clear(&attempt);
    return rc;
}

static int extra_add(br_result *result, const char *key, const char *value, char **error)
{
    if (!result->extra_data && !(result->extra_data = json_object_new_object()))
        return fail(error, "cannot create Postgres metadata");
    br_json *item = json_object_new_string(value);
    if (!item) return fail(error, "cannot create Postgres metadata");
    if (json_object_object_add(result->extra_data, key, item) != 0) {
        json_object_put(item);
        return fail(error, "cannot create Postgres metadata");
    }
    return 0;
}

static int attach_extra(br_result *result, const pg_params *params, char **error)
{
    const char *sslmode = params_get(params, "sslmode");
    const char *host = params_get(params, "host");
    const char *port = params_get(params, "port");
    const char *user = params_get(params, "user");
    const char *dbname = params_get(params, "dbname");
    if (extra_add(result, "sslmode", sslmode && *sslmode ? sslmode : "<unset>", error) != 0) return -1;
    if (host && *host) {
        size_t hn = strlen(host), pn = port && *port ? strlen(port) : 0;
        if (hn > SIZE_MAX - 3 || pn > SIZE_MAX - 3 - hn) return fail(error, "Postgres endpoint is too large");
        size_t need = hn + 1 + (pn ? pn + 1 : 0);
        char *endpoint = malloc(need + 1);
        if (!endpoint) return fail(error, "cannot format Postgres endpoint");
        if (port && *port) snprintf(endpoint, need + 1, "%s:%s", host, port);
        else snprintf(endpoint, need + 1, "%s", host);
        int added = extra_add(result, "host", endpoint, error);
        free(endpoint);
        if (added) return -1;
    }
    if (user && *user && extra_add(result, "username", user, error) != 0) return -1;
    if (dbname && *dbname && extra_add(result, "database", dbname, error) != 0) return -1;
    return 0;
}

typedef struct { pg_hits *hits; char *error; const unsigned char *data; } hit_box;

static int take_uri(void *user, const br_span *groups, size_t ngroups)
{
    hit_box *box = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end < groups[0].begin ||
        ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end < groups[1].begin)
        return fail(&box->error, "invalid Postgres URI capture");
    if (box->hits->len == box->hits->cap) {
        if (box->hits->cap > SIZE_MAX / sizeof(*box->hits->items) / 2)
            return fail(&box->error, "too many Postgres URIs");
        size_t cap = box->hits->cap ? box->hits->cap * 2 : 4;
        pg_hit *items = realloc(box->hits->items, cap * sizeof(*items));
        if (!items) return fail(&box->error, "cannot retain Postgres URI");
        box->hits->items = items;
        box->hits->cap = cap;
    }
    pg_hit hit = {
        dup_len((const char *)box->data + groups[0].begin, groups[0].end - groups[0].begin),
        dup_len((const char *)box->data + groups[1].begin, groups[1].end - groups[1].begin),
    };
    if (!hit.uri || !hit.scheme) {
        free(hit.uri);
        free(hit.scheme);
        return fail(&box->error, "cannot retain Postgres URI");
    }
    box->hits->items[box->hits->len++] = hit;
    return 0;
}

static void hits_clear(pg_hits *hits)
{
    if (!hits) return;
    for (size_t i = 0; i < hits->len; ++i) {
        free(hits->items[i].uri);
        free(hits->items[i].scheme);
    }
    free(hits->items);
    *hits = (pg_hits){0};
}

static bool postgres_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = NULL;
    return false;
}

static int scan_postgres(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !part_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Postgres scan");
    size_t original_len = out->len;
    pg_hits hits = {0};
    hit_box box = {&hits, NULL, input.data};
    char *owned_error = NULL;
    int rc = br_regex_each(uri_re, input, take_uri, &box, &owned_error);
    if (box.error) {
        if (!owned_error) owned_error = box.error;
        else free(box.error);
        rc = -1;
    }
    if (!rc && hits.len && !ctx) rc = fail(&owned_error, "unsupported upstream panic: Postgres nil context");
    for (size_t i = 0; !rc && i < hits.len; ++i) {
        if (is_done(ctx, &owned_error)) {
            if (owned_error) rc = -1;
            break;
        }
        bool skip = false;
        if (should_ignore((br_slice){(const unsigned char *)hits.items[i].uri, strlen(hits.items[i].uri)},
                          &skip, &owned_error) != 0) {
            rc = -1;
            break;
        }
        if (skip) continue;
        pg_params params = {0};
        int parsed = parse_uri(hits.items[i].uri, hits.items[i].scheme, &params, &owned_error);
        if (parsed < 0) {
            rc = -1;
            break;
        }
        if (parsed > 0) continue;
        const char *user = params_get(&params, "user");
        const char *password = params_get(&params, "password");
        const char *host = params_get(&params, "host");
        if (!user || !password || !host ||
            (!detect_loopback && loopback_host(host))) {
            params_clear(&params);
            continue;
        }
        if (!params_get(&params, "port") && params_set(&params, "port", "5432", &owned_error) != 0) {
            params_clear(&params);
            rc = -1;
            break;
        }
        const char *requiressl = params_get(&params, "requiressl");
        if (requiressl && !strcmp(requiressl, "0") &&
            params_set(&params, "sslmode", "prefer", &owned_error) != 0) {
            params_clear(&params);
            rc = -1;
            break;
        }
        if (requiressl && !strcmp(requiressl, "1") &&
            params_set(&params, "sslmode", "require", &owned_error) != 0) {
            params_clear(&params);
            rc = -1;
            break;
        }
        if (verify && ctx->deadline_monotonic_ms) {
            int64_t now = now_ms();
            if (now < 0) {
                fail(&owned_error, "monotonic clock unavailable");
                params_clear(&params);
                rc = -1;
                break;
            }
            int seconds = (int)((ctx->deadline_monotonic_ms - now) / 1000);
            if (ctx->deadline_monotonic_ms <= now) seconds = -1;
            if (seconds <= 0) {
                params_clear(&params);
                break;
            }
            char timeout[32];
            snprintf(timeout, sizeof(timeout), "%d", seconds);
            if (params_set(&params, "connect_timeout", timeout, &owned_error) != 0) {
                params_clear(&params);
                rc = -1;
                break;
            }
        }
        const char *port = params_get(&params, "port");
        const char *scheme = params_get(&params, "db_type");
        int raw_len = snprintf(NULL, 0, "%s://%s:%s@%s:%s", scheme, user, password, host, port);
        char *raw = raw_len < 0 ? NULL : malloc((size_t)raw_len + 1);
        br_result result = {0};
        if (!raw) {
            fail(&owned_error, "cannot format Postgres result");
            params_clear(&params);
            rc = -1;
            break;
        }
        snprintf(raw, (size_t)raw_len + 1, "%s://%s:%s@%s:%s", scheme, user, password, host, port);
        if (br_finding_key_bytes(&result, detector->type,
                                 (br_slice){(const unsigned char *)raw, strlen(raw)},
                                 "connection_string") != 0) {
            free(raw);
            fail(&owned_error, "cannot create Postgres result");
            params_clear(&params);
            rc = -1;
            break;
        }
        result.raw_v2.data = (unsigned char *)dup_len(raw, strlen(raw));
        result.raw_v2.len = strlen(raw);
        result.primary_secret.data = (unsigned char *)dup_len(hits.items[i].uri, strlen(hits.items[i].uri));
        result.primary_secret.len = strlen(hits.items[i].uri);
        free(raw);
        if (!result.raw_v2.data || !result.primary_secret.data ||
            attach_extra(&result, &params, &owned_error) != 0 ||
            (verify && verify_params(ctx, &params, &result, &owned_error) != 0) ||
            br_results_push(out, &result) != 0) {
            if (!owned_error) fail(&owned_error, "cannot append Postgres result");
            br_result_clear(&result);
            params_clear(&params);
            rc = -1;
            break;
        }
        params_clear(&params);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    hits_clear(&hits);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"postgres"};
static br_detector postgres = {
    .type = 968, .version = 0, .name = "Postgres", .custom_name = "",
    .description = "Postgres connection string containing credentials",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_postgres, .false_positive = postgres_false_positive,
};

int br_postgres_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Postgres detector output");
    *out = NULL;
    if (!uri_re && br_regex_compile("\\b(?i)(postgres(?:ql)?)://\\S+\\b", &uri_re, error) != 0)
        return -1;
    if (!part_re && br_regex_compile("([[:alpha:]]+)='(.+?)' ?", &part_re, error) != 0)
        return -1;
    postgres.state = uri_re;
    *out = &postgres;
    return 0;
}
