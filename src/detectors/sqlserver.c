/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sqlserver/sqlserver.go.
 * msdsn v1.8.2 Parse/URL projection. Verification does not dial or open SQL. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

typedef struct { char *name, *value; } kv;
typedef struct {
    kv *items;
    size_t len, cap;
    char *host, *instance, *database, *user, *password, *protocol;
    unsigned port;
    int encrypt; /* 0 off, 1 required, 3 disabled */
    bool disable_retry, skip;
    int protocols;
    char *cause;
} mssql_cfg;

static void cfg_clear(mssql_cfg *cfg)
{
    for (size_t i = 0; i < cfg->len; ++i) { free(cfg->items[i].name); free(cfg->items[i].value); }
    free(cfg->items); free(cfg->host); free(cfg->instance); free(cfg->database);
    free(cfg->user); free(cfg->password); free(cfg->protocol); free(cfg->cause);
    *cfg = (mssql_cfg){0};
}

static int kv_set(mssql_cfg *cfg, const char *name, const char *value)
{
    for (size_t i = 0; i < cfg->len; ++i) {
        if (!strcmp(cfg->items[i].name, name)) {
            char *copy = strdup(value);
            if (!copy) return -1;
            free(cfg->items[i].value);
            cfg->items[i].value = copy;
            return 0;
        }
    }
    if (cfg->len == cfg->cap) {
        if (cfg->cap > SIZE_MAX / sizeof(*cfg->items) / 2) return -1;
        size_t cap = cfg->cap ? cfg->cap * 2 : 8;
        kv *grown = realloc(cfg->items, cap * sizeof(*grown));
        if (!grown) return -1;
        cfg->items = grown;
        cfg->cap = cap;
    }
    char *name_copy = strdup(name), *value_copy = strdup(value);
    if (!name_copy || !value_copy) { free(name_copy); free(value_copy); return -1; }
    cfg->items[cfg->len] = (kv){name_copy, value_copy};
    ++cfg->len;
    return 0;
}

static const char *kv_get(const mssql_cfg *cfg, const char *name)
{
    for (size_t i = 0; i < cfg->len; ++i)
        if (!strcmp(cfg->items[i].name, name)) return cfg->items[i].value;
    return NULL;
}

static char *trim_dup(const char *start, size_t n, bool lower)
{
    if (n == SIZE_MAX) return NULL;
    while (n && (*start == ' ' || *start == '\t')) { ++start; --n; }
    while (n && (start[n - 1] == ' ' || start[n - 1] == '\t')) --n;
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, start, n);
    out[n] = '\0';
    if (lower) {
        for (size_t i = 0; i < n; ++i)
            if (out[i] >= 'A' && out[i] <= 'Z') out[i] = (char)(out[i] - 'A' + 'a');
    }
    return out;
}

static const char *synonym(const char *name)
{
    if (!strcmp(name, "application name")) return "app name";
    if (!strcmp(name, "data source") || !strcmp(name, "address") ||
        !strcmp(name, "network address") || !strcmp(name, "addr")) return "server";
    if (!strcmp(name, "user") || !strcmp(name, "uid")) return "user id";
    if (!strcmp(name, "pwd")) return "password";
    if (!strcmp(name, "initial catalog")) return "database";
    if (!strcmp(name, "column encryption setting")) return "columnencryption";
    return name;
}

static int split_ado(mssql_cfg *cfg, const char *dsn)
{
    const char *at = dsn;
    while (*at) {
        const char *semi = strchr(at, ';');
        size_t n = semi ? (size_t)(semi - at) : strlen(at);
        if (n) {
            const char *eq = memchr(at, '=', n);
            size_t name_n = eq ? (size_t)(eq - at) : n;
            char *name = trim_dup(at, name_n, true);
            char *value = trim_dup(eq ? eq + 1 : "", eq ? n - name_n - 1 : 0, false);
            if (!name || !value) { free(name); free(value); return -1; }
            if (name[0]) {
                const char *canon = synonym(name);
                if (!strcmp(canon, "server")) {
                    if (!strncmp(value, "tcp:", 4)) {
                        if (kv_set(cfg, "protocol", "tcp") != 0) { free(name); free(value); return -1; }
                        memmove(value, value + 4, strlen(value + 4) + 1);
                    } else if (!strncmp(value, "admin:", 6)) {
                        if (kv_set(cfg, "protocol", "admin") != 0) { free(name); free(value); return -1; }
                        memmove(value, value + 6, strlen(value + 6) + 1);
                    }
                    char *comma = strchr(value, ',');
                    if (comma && comma[1] && !strchr(comma + 1, ',')) {
                        *comma = '\0';
                        if (kv_set(cfg, "port", comma + 1) != 0) { free(name); free(value); return -1; }
                    }
                }
                if (kv_set(cfg, canon, value) != 0) { free(name); free(value); return -1; }
            }
            free(name);
            free(value);
        }
        if (!semi) break;
        at = semi + 1;
    }
    return 0;
}

static int parse_u16(const char *text, unsigned *out, const char *what, mssql_cfg *cfg)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (!text[0] || *end || value > 65535) {
        char message[128];
        snprintf(message, sizeof(message), "invalid %s '%s'", what, text);
        cfg->cause = strdup(message);
        cfg->skip = true;
        return cfg->cause ? 0 : -1;
    }
    *out = (unsigned)value;
    return 0;
}

static int parse_server(mssql_cfg *cfg, const char *prefix, bool hidden)
{
    const char *protocol = kv_get(cfg, "protocol");
    if (protocol && strcmp(protocol, prefix)) return 0;
    if (!protocol && hidden) return 0;
    const char *server = kv_get(cfg, "server");
    if (!server) server = "";
    const char *slash = strchr(server, '\\');
    size_t host_n = slash ? (size_t)(slash - server) : strlen(server);
    char *host = malloc(host_n + 1);
    if (!host) return -1;
    memcpy(host, server, host_n);
    host[host_n] = '\0';
    if (!strcmp(host, ".") || !host[0] || !strcasecmp(host, "(local)")) {
        free(host);
        host = strdup("localhost");
        if (!host) return -1;
    }
    free(cfg->host);
    cfg->host = host;
    free(cfg->instance);
    cfg->instance = strdup(slash ? slash + 1 : "");
    if (!cfg->instance) return -1;
    if (!strcmp(prefix, "admin") && !cfg->instance[0]) cfg->port = 1434;
    ++cfg->protocols;
    return 0;
}

static int parse_cfg(const char *dsn, mssql_cfg *cfg)
{
    *cfg = (mssql_cfg){0};
    if (split_ado(cfg, dsn) != 0) return -1;
    const char *port = kv_get(cfg, "port");
    if (port && parse_u16(port, &cfg->port, "tcp port", cfg) != 0) return -1;
    if (cfg->skip) return 0;
    const char *retry = kv_get(cfg, "disableretry");
    if (retry) {
        if (!strcmp(retry, "1") || !strcmp(retry, "t") || !strcmp(retry, "T") ||
            !strcmp(retry, "true") || !strcmp(retry, "TRUE") || !strcmp(retry, "True"))
            cfg->disable_retry = true;
        else if (!strcmp(retry, "0") || !strcmp(retry, "f") || !strcmp(retry, "F") ||
                 !strcmp(retry, "false") || !strcmp(retry, "FALSE") || !strcmp(retry, "False"))
            cfg->disable_retry = false;
        else {
            cfg->skip = true;
            return 0;
        }
    }
    if (parse_server(cfg, "tcp", false) != 0 || parse_server(cfg, "admin", true) != 0) return -1;
    if (kv_get(cfg, "protocol") && !cfg->protocols) {
        cfg->skip = true;
        return 0;
    }
    const char *encrypt = kv_get(cfg, "encrypt");
    char encrypt_buf[64];
    if (encrypt) {
        size_t elen = strlen(encrypt);
        if (elen >= sizeof(encrypt_buf)) { cfg->skip = true; return 0; }
        for (size_t i = 0; i < elen; ++i)
            encrypt_buf[i] = encrypt[i] >= 'A' && encrypt[i] <= 'Z' ? (char)(encrypt[i] - 'A' + 'a') : encrypt[i];
        encrypt_buf[elen] = '\0';
        encrypt = encrypt_buf;
        if (!strcmp(encrypt, "mandatory") || !strcmp(encrypt, "yes") || !strcmp(encrypt, "1") ||
            !strcmp(encrypt, "t") || !strcmp(encrypt, "true")) cfg->encrypt = 1;
        else if (!strcmp(encrypt, "disable")) cfg->encrypt = 3;
        else if (!strcmp(encrypt, "strict") || !strcmp(encrypt, "optional") ||
                 !strcmp(encrypt, "no") || !strcmp(encrypt, "0") || !strcmp(encrypt, "f") ||
                 !strcmp(encrypt, "false")) cfg->encrypt = 0;
        else {
            char message[128];
            snprintf(message, sizeof(message), "invalid encrypt '%s'", encrypt);
            cfg->cause = strdup(message);
            cfg->skip = true;
            return cfg->cause ? 0 : -1;
        }
    }
    cfg->database = strdup(kv_get(cfg, "database") ? kv_get(cfg, "database") : "");
    cfg->user = strdup(kv_get(cfg, "user id") ? kv_get(cfg, "user id") : "");
    cfg->password = strdup(kv_get(cfg, "password") ? kv_get(cfg, "password") : "");
    if (!cfg->database || !cfg->user || !cfg->password || !cfg->host) {
        if (!cfg->host) cfg->host = strdup("");
        if (!cfg->host || !cfg->database || !cfg->user || !cfg->password) return -1;
    }
    if (kv_get(cfg, "certificate") && cfg->encrypt != 3)
        return fail(&cfg->cause, "unsupported: SQL Server certificate file is not read");
    return 0;
}

static int escape_mode(const char *in, bool query, char **out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = strlen(in);
    if (n > (SIZE_MAX - 1) / 3) return -1;
    char *text = malloc(n * 3 + 1);
    if (!text) return -1;
    size_t at = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)in[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (!query && (c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
                       c == '*' || c == '+' || c == ',' || c == ';' || c == '=')) plain = true;
        if (query && c == ' ') text[at++] = '+';
        else if (plain) text[at++] = (char)c;
        else {
            text[at++] = '%';
            text[at++] = hex[c >> 4];
            text[at++] = hex[c & 15];
        }
    }
    text[at] = '\0';
    *out = text;
    return 0;
}

static int build_url(const mssql_cfg *cfg, bool clean, char **out)
{
    char *user = NULL, *pass = NULL, *db_esc = NULL, *query = NULL, *url = NULL;
    if (escape_mode(cfg->user ? cfg->user : "", false, &user) != 0 ||
        escape_mode(cfg->password ? cfg->password : "", false, &pass) != 0)
        goto oom;
    const char *db = cfg->database ? cfg->database : "";
    if (db[0] && escape_mode(db, true, &db_esc) != 0) goto oom;
    int protocols = cfg->protocols ? cfg->protocols : 1;
    int dial = clean ? 3 : 15 * protocols;
    const char *retry = (clean || cfg->disable_retry) ? "true" : "false";
    const char *enc = cfg->encrypt == 3 ? "DISABLE" : cfg->encrypt == 1 ? "true" : NULL;
    const char *protocol = kv_get(cfg, "protocol");
    char sorted[512];
    int n = snprintf(sorted, sizeof(sorted), "%s%s%sdial+timeout=%d&disableretry=%s%s%s%s%s",
                     db_esc ? "database=" : "", db_esc ? db_esc : "", db_esc ? "&" : "",
                     dial, retry, enc ? "&encrypt=" : "", enc ? enc : "",
                     protocol ? "&protocol=" : "", protocol ? protocol : "");
    if (n < 0 || (size_t)n >= sizeof(sorted)) goto oom;
    /* database, dial+timeout, disableretry, encrypt, protocol is already sorted. */
    query = strdup(sorted);
    if (!query) goto oom;
    const char *host = cfg->host ? cfg->host : "";
    const char *instance = cfg->instance && cfg->instance[0] ? cfg->instance : NULL;
    n = snprintf(NULL, 0, "sqlserver://%s:%s@%s%s%u%s%s?%s",
                 user, pass, host, cfg->port ? ":" : "", cfg->port ? cfg->port : 0,
                 instance ? "/" : "", instance ? instance : "", query);
    if (n < 0) goto oom;
    url = malloc((size_t)n + 1);
    if (!url) goto oom;
    if (cfg->port)
        snprintf(url, (size_t)n + 1, "sqlserver://%s:%s@%s:%u%s%s?%s",
                 user, pass, host, cfg->port, instance ? "/" : "", instance ? instance : "", query);
    else
        snprintf(url, (size_t)n + 1, "sqlserver://%s:%s@%s%s%s?%s",
                 user, pass, host, instance ? "/" : "", instance ? instance : "", query);
    free(user); free(pass); free(db_esc); free(query);
    *out = url;
    return 0;
oom:
    free(user); free(pass); free(db_esc); free(query); free(url);
    return -1;
}

static int redact_url(const char *url, char **out)
{
    const char *at = strstr(url, "://");
    const char *colon = at ? strchr(at + 3, ':') : NULL;
    const char *host = colon ? strchr(colon + 1, '@') : NULL;
    if (!at || !colon || !host) return -1;
    size_t head = (size_t)(colon + 1 - url), tail = strlen(host);
    if (head > SIZE_MAX - 9 || tail > SIZE_MAX - 9 - head) return -1;
    size_t n = head + 8 + tail;
    char *text = malloc(n + 1);
    if (!text) return -1;
    memcpy(text, url, head);
    memcpy(text + head, "********", 8);
    memcpy(text + head + 8, host, strlen(host) + 1);
    *out = text;
    return 0;
}

/* address is the optional TCP pre-check target. NULL means skip the pre-check
 * and let the injected driver resolve the named instance from dsn. It does not
 * mean skip credential verification. The callback must tolerate NULL address. */
typedef int (*sqlserver_ping_fn)(const br_scan_ctx *ctx, const char *address, const char *dsn,
                                 bool *verified, bool *is_mssql, int32_t *number,
                                 char **ordinary, char **fatal);
typedef struct {
    br_regex *pattern;
    br_regex **ignore;
    size_t nignore;
    sqlserver_ping_fn ping;
} sqlserver_state;

static sqlserver_state *sql_state;

int br_sqlserver_set_ping(sqlserver_ping_fn ping)
{
    if (!sql_state) return -1;
    sql_state->ping = ping;
    return 0;
}

static int add_part(br_result *result, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value ? value : "");
    if (!part || json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int verify_sql(const br_scan_ctx *ctx, const mssql_cfg *cfg, br_result *result, char **error)
{
    if (!ctx) return fail(error, "unsupported upstream panic: SQL Server nil context");
    if (!sql_state || !sql_state->ping)
        return fail(error, "unsupported: SQL Server verification without injected ping");
    char address[128];
    const char *pre_dial = NULL;
    if (cfg->port || !cfg->instance || !cfg->instance[0]) {
        const char *host = cfg->host ? cfg->host : "";
        unsigned port = cfg->port ? cfg->port : 1433;
        bool ipv6 = strchr(host, ':') != NULL;
        int n = snprintf(address, sizeof(address), "%s%s%s:%u",
                         ipv6 ? "[" : "", host, ipv6 ? "]" : "", port);
        if (n < 0 || (size_t)n >= sizeof(address)) return fail(error, "cannot format SQL Server address");
        pre_dial = address;
    }
    char *dsn = NULL;
    if (build_url(cfg, true, &dsn) != 0) return fail(error, "cannot format SQL Server verification URL");
    bool verified = false, is_mssql = false;
    int32_t number = 0;
    char *ordinary = NULL, *fatal = NULL;
    int rc = sql_state->ping(ctx, pre_dial, dsn, &verified, &is_mssql, &number, &ordinary, &fatal);
    free(dsn);
    if (rc < 0) {
        if (error && !*error) *error = fatal ? fatal : strdup("unsupported: SQL Server ping failed");
        else free(fatal);
        free(ordinary);
        return -1;
    }
    free(fatal);
    if (rc == 0 && verified) result->verified = true;
    else if (is_mssql && number == 18456) {
        /* Determinate login failure stays quiet. */
    } else if (is_mssql) {
        char message[256];
        snprintf(message, sizeof(message), "SQL Server error %d: %s", number, ordinary ? ordinary : "");
        br_slice secret = {(const unsigned char *)cfg->password, strlen(cfg->password)};
        if (br_result_set_verification_error(result, message, &secret, 1) != 0) {
            free(ordinary);
            return fail(error, "cannot set SQL Server verification error");
        }
    } else if (ordinary) {
        br_slice secret = {(const unsigned char *)cfg->password, strlen(cfg->password)};
        if (br_result_set_verification_error(result, ordinary, &secret, 1) != 0) {
            free(ordinary);
            return fail(error, "cannot set SQL Server verification error");
        }
    }
    free(ordinary);
    return 0;
}

static int ignore_hit(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups; (void)ngroups;
    *(bool *)user = true;
    return 0;
}

static int ignored(const sqlserver_state *state, const char *text)
{
    br_slice input = {(const unsigned char *)text, strlen(text)};
    for (size_t i = 0; i < state->nignore; ++i) {
        bool hit = false;
        char *error = NULL;
        int rc = br_regex_each(state->ignore[i], input, ignore_hit, &hit, &error);
        free(error);
        if (rc < 0) return -1;
        if (hit) return 1;
    }
    return 0;
}

int br_sqlserver_set_ignore(const char *const *patterns, size_t count, char **error)
{
    if (error) *error = NULL;
    if (!sql_state || (count && !patterns)) return fail(error, "invalid SQL Server ignore patterns");
    if (count > SIZE_MAX / sizeof(br_regex *)) return fail(error, "too many SQL Server ignore patterns");
    br_regex **next = count ? calloc(count, sizeof(*next)) : NULL;
    if (count && !next) return fail(error, "cannot allocate SQL Server ignore patterns");
    for (size_t i = 0; i < count; ++i) {
        if (br_regex_compile(patterns[i], &next[i], error) != 0) {
            for (size_t j = 0; j <= i; ++j) br_regex_free(next[j]);
            free(next);
            return -1;
        }
    }
    for (size_t i = 0; i < sql_state->nignore; ++i) br_regex_free(sql_state->ignore[i]);
    free(sql_state->ignore);
    sql_state->ignore = next;
    sql_state->nignore = count;
    return 0;
}

static int scan_sqlserver(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    sqlserver_state *state = detector ? (sqlserver_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SQL Server scan");
    size_t before = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(state->pattern, input, &found, false, &owned);
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_slice match = br_captures_at(&found, i);
        char *text = malloc(match.len + 1);
        if (!text) { rc = fail(&owned, "cannot copy SQL Server capture"); break; }
        memcpy(text, match.data, match.len);
        text[match.len] = '\0';
        int skip = ignored(state, text);
        if (skip < 0) rc = fail(&owned, "cannot apply SQL Server ignore pattern");
        mssql_cfg cfg = {0};
        if (!rc && !skip) {
            rc = parse_cfg(text, &cfg);
            if (rc && cfg.cause && !owned) { owned = cfg.cause; cfg.cause = NULL; }
        }
        if (!rc && cfg.cause && strstr(cfg.cause, "unsupported:")) {
            if (!owned) owned = cfg.cause;
            cfg.cause = NULL;
            rc = -1;
        }
        if (!rc && !skip && !cfg.skip && cfg.password && cfg.password[0]) {
            char *url = NULL, *redacted = NULL;
            if (build_url(&cfg, false, &url) != 0 || redact_url(url, &redacted) != 0)
                rc = fail(&owned, "cannot format SQL Server URL");
            br_result result = {0};
            br_slice secret = {(const unsigned char *)cfg.password, strlen(cfg.password)};
            if (!rc && br_finding_key_bytes(&result, detector->type, secret, "password") != 0)
                rc = fail(&owned, "cannot create SQL Server finding");
            if (!rc && (add_part(&result, "host", cfg.host) != 0 ||
                        add_part(&result, "database", cfg.database) != 0 ||
                        add_part(&result, "user", cfg.user) != 0))
                rc = fail(&owned, "cannot store SQL Server secret parts");
            if (!rc) {
                result.raw_v2.len = strlen(url);
                result.raw_v2.data = malloc(result.raw_v2.len ? result.raw_v2.len : 1);
                result.redacted = redacted;
                redacted = NULL;
                if (!result.raw_v2.data) rc = fail(&owned, "cannot store SQL Server URL");
                else memcpy(result.raw_v2.data, url, result.raw_v2.len);
            }
            if (!rc && verify) rc = verify_sql(ctx, &cfg, &result, &owned);
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append SQL Server finding");
            br_result_clear(&result);
            free(url);
            free(redacted);
        }
        cfg_clear(&cfg);
        free(text);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sql", "database", "Data Source", "Server=", "Network address="};
static br_detector sqlserver = {
    .type = 898, .version = 0, .name = "SQLServer", .custom_name = "",
    .description = "SQL Server is a relational database management system developed by Microsoft. SQL Server credentials can be used to access and manage databases.",
    .keywords = keywords, .nkeywords = 5,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_sqlserver,
};

int br_sqlserver_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SQL Server detector output");
    *out = NULL;
    if (sqlserver.state) { *out = &sqlserver; return 0; }
    sqlserver_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate SQL Server pattern");
    if (br_regex_compile("(?:\\n|`|'|\"| )?((?:[A-Za-z0-9_ ]+=[^;$'`\"$]+;?){3,})(?:'|`|\"|\\r\\n|\\n)?",
                         &state->pattern, error) != 0) {
        free(state);
        return -1;
    }
    sqlserver.state = state;
    sql_state = state;
    *out = &sqlserver;
    return 0;
}
