/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ldap/ldap.go. */
#include "detectors.h"
#include "captures.h"
#include "ldap_private.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ldap_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static const char uri_pattern[] = "\\b(?i)ldaps?://[^\\t\\n\\f\\r ]+\\b";
static const char username_suffix[] = "[\"']([a-zA-Z=,]{4,150})[\"']";
static const char password_suffix[] = "[\"']([^\\t\\n\\f\\r ]{4,48})[\"']";
static const char iad_pattern[] =
    "OpenDSObject\\(\"(?i)(ldaps?://[^\\t\\n\\f\\r ]+)\", ?\"([^\\t\\n\\f\\r ]+)\", ?\"([^\\t\\n\\f\\r ]+)\",[ \\d]+\\)";
static const char *const username_keywords[] = {"user", "bind"};
static const char *const password_keywords[] = {"pass"};
static const int64_t dial_timeout_ns = INT64_C(5000000000);

static br_ldap_state ldap_state;

static int add_part(br_result *result, const char *name, br_slice value)
{
    if ((!value.data && value.len) || value.len > INT_MAX) return -1;
    if (!result->secret_parts) {
        result->secret_parts = json_object_new_object();
        if (!result->secret_parts) return -1;
    }
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part) return -1;
    if (json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int make_finding(br_result *result, br_slice url, br_slice username, br_slice password)
{
    if ((!url.data && url.len) || (!username.data && username.len) || (!password.data && password.len))
        return -1;
    if (username.len > SIZE_MAX - url.len - 2 || password.len > SIZE_MAX - url.len - username.len - 2)
        return -1;
    size_t raw_len = url.len + username.len + password.len + 2;
    result->detector_type = 901;
    result->raw.data = malloc(raw_len ? raw_len : 1);
    if (!result->raw.data) return -1;
    if (url.len) memcpy(result->raw.data, url.data, url.len);
    result->raw.data[url.len] = '\t';
    if (username.len) memcpy(result->raw.data + url.len + 1, username.data, username.len);
    result->raw.data[url.len + username.len + 1] = '\t';
    if (password.len) memcpy(result->raw.data + url.len + username.len + 2, password.data, password.len);
    result->raw.len = raw_len;
    if (add_part(result, "url", url) || add_part(result, "username", username) ||
        add_part(result, "password", password))
        return -1;
    return 0;
}

static void release_call(br_ldap_error *ordinary, char **fatal)
{
    br_ldap_error_clear(ordinary);
    if (fatal && *fatal) {
        free(*fatal);
        *fatal = NULL;
    }
}

static int quote_go(br_slice text, char **out, char **error)
{
    static const char hex[] = "0123456789abcdef";
    if (!out || (!text.data && text.len)) return ldap_fail(error, "invalid LDAP scheme");
    *out = NULL;
    size_t n = 2;
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        size_t add = 1;
        if (c >= 128) return ldap_fail(error, "unsupported: LDAP non-ASCII scheme quoting");
        if (c < 32 || c == 127 || c == '\\' || c == '"') add = (c < 32 || c == 127) &&
            c != '\a' && c != '\b' && c != '\f' && c != '\n' && c != '\r' && c != '\t' && c != '\v' ? 4 : 2;
        if (n > SIZE_MAX - add) return ldap_fail(error, "LDAP scheme is too large");
        n += add;
    }
    char *quoted = malloc(n + 1);
    if (!quoted) return ldap_fail(error, "cannot quote LDAP scheme");
    size_t at = 0;
    quoted[at++] = '"';
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        const char *esc = NULL;
        switch (c) {
        case '\a': esc = "\\a"; break; case '\b': esc = "\\b"; break;
        case '\f': esc = "\\f"; break; case '\n': esc = "\\n"; break;
        case '\r': esc = "\\r"; break; case '\t': esc = "\\t"; break;
        case '\v': esc = "\\v"; break; case '\\': esc = "\\\\"; break; case '"': esc = "\\\""; break;
        default: break;
        }
        if (esc) { memcpy(quoted + at, esc, 2); at += 2; }
        else if (c < 32 || c == 127) {
            quoted[at++] = '\\'; quoted[at++] = 'x';
            quoted[at++] = hex[c >> 4]; quoted[at++] = hex[c & 15];
        } else quoted[at++] = (char)c;
    }
    quoted[at++] = '"';
    quoted[at] = '\0';
    *out = quoted;
    return 0;
}

/* Determinate. The formatted error is intentionally not published. */
static int unknown_scheme(br_slice url, char **error)
{
    size_t colon = 0;
    while (colon < url.len && url.data && url.data[colon] != ':') ++colon;
    char *quoted = NULL;
    if (quote_go((br_slice){url.data, colon}, &quoted, error)) return -1;
    int n = snprintf(NULL, 0, "unknown ldap scheme %s", quoted);
    if (n < 0) {
        free(quoted);
        return ldap_fail(error, "cannot format LDAP scheme error");
    }
    char *text = malloc((size_t)n + 1);
    if (!text) {
        free(quoted);
        return ldap_fail(error, "cannot format LDAP scheme error");
    }
    int wrote = snprintf(text, (size_t)n + 1, "unknown ldap scheme %s", quoted);
    free(quoted);
    free(text);
    if (wrote < 0 || (size_t)wrote >= (size_t)n + 1)
        return ldap_fail(error, "cannot format LDAP scheme error");
    return 0;
}

/* A reached ldap or ldaps dial checks nil context before missing I/O. */
static int begin_dial(const br_ldap_state *state, const br_scan_ctx *ctx, char **error)
{
    if (!ctx) return ldap_fail(error, "unsupported upstream panic: LDAP nil context");
    if (!state->io) return ldap_fail(error, "unsupported: LDAP verification");
    return 0;
}

static int classify(br_result *result, const br_ldap_error *ordinary, br_slice password, char **error)
{
    if (ordinary->presence == BR_LDAP_ERR_NONE) {
        result->verified = true;
        return 0;
    }
    if (ordinary->presence != BR_LDAP_ERR_OTHER)
        return ldap_fail(error, "unsupported: LDAP error presence");
    if (!ordinary->has_op_error && !ordinary->is_deadline && !ordinary->is_canceled)
        return 0;
    if (ordinary->innermost.len && !ordinary->innermost.data)
        return ldap_fail(error, "unsupported: LDAP verification error");
    if (ordinary->innermost.data && memchr(ordinary->innermost.data, '\0', ordinary->innermost.len))
        return ldap_fail(error, "unsupported: LDAP verification error contains embedded NUL");
    char *cause = malloc(ordinary->innermost.len + 1);
    if (!cause) return ldap_fail(error, "cannot store LDAP verification error");
    if (ordinary->innermost.len) memcpy(cause, ordinary->innermost.data, ordinary->innermost.len);
    cause[ordinary->innermost.len] = '\0';
    int rc = br_result_set_verification_error(result, cause, &password, 1);
    free(cause);
    if (rc != 0) return ldap_fail(error, "cannot store LDAP verification error");
    return 0;
}

/* A failed dial is not closed. Success must transfer a handle before bind or StartTLS. */
static int after_dial(void *handle, int dial_rc, br_ldap_error *ordinary, char **fatal,
                      br_result *result, br_slice password, bool *live, char **error)
{
    *live = false;
    if (dial_rc != 0) {
        release_call(ordinary, fatal);
        return ldap_fail(error, "LDAP dial failed");
    }
    if (ordinary->presence != BR_LDAP_ERR_NONE) {
        int classified = classify(result, ordinary, password, error);
        release_call(ordinary, fatal);
        return classified;
    }
    release_call(ordinary, fatal);
    if (!handle) return ldap_fail(error, "unsupported: LDAP NULL dial handle");
    *live = true;
    return 0;
}

static int verify_ldap(const br_ldap_state *state, const br_scan_ctx *ctx, br_slice url,
                       br_slice username, br_slice password, br_result *result, char **error)
{
    if (begin_dial(state, ctx, error)) return -1;
    const br_ldap_io *io = state->io;
    void *user = state->io_user;
    void *handle = NULL;
    br_ldap_error ordinary = {0};
    char *fatal = NULL;
    int dial_rc = io->dial(user, url, false, false, ctx, dial_timeout_ns, &handle, &ordinary, &fatal);
    bool live = false;
    int rc = after_dial(handle, dial_rc, &ordinary, &fatal, result, password, &live, error);
    if (!live) return rc;

    rc = io->bind(user, handle, ctx, username, password, &ordinary, &fatal);
    if (rc != 0) {
        io->close(user, handle);
        release_call(&ordinary, &fatal);
        return ldap_fail(error, "LDAP bind failed");
    }
    if (ordinary.presence == BR_LDAP_ERR_NONE) {
        io->close(user, handle);
        result->verified = true;
        release_call(&ordinary, &fatal);
        return 0;
    }
    release_call(&ordinary, &fatal);

    rc = io->starttls(user, handle, true, &ordinary, &fatal);
    if (rc != 0) {
        io->close(user, handle);
        release_call(&ordinary, &fatal);
        return ldap_fail(error, "LDAP StartTLS failed");
    }
    if (ordinary.presence != BR_LDAP_ERR_NONE) {
        io->close(user, handle);
        int classified = classify(result, &ordinary, password, error);
        release_call(&ordinary, &fatal);
        return classified;
    }
    release_call(&ordinary, &fatal);

    rc = io->bind(user, handle, ctx, username, password, &ordinary, &fatal);
    if (rc != 0) {
        io->close(user, handle);
        release_call(&ordinary, &fatal);
        return ldap_fail(error, "LDAP bind failed");
    }
    io->close(user, handle);
    int classified = classify(result, &ordinary, password, error);
    release_call(&ordinary, &fatal);
    return classified;
}

static int verify_ldaps(const br_ldap_state *state, const br_scan_ctx *ctx, br_slice url,
                        br_slice username, br_slice password, br_result *result, char **error)
{
    if (begin_dial(state, ctx, error)) return -1;
    const br_ldap_io *io = state->io;
    void *user = state->io_user;
    void *handle = NULL;
    br_ldap_error ordinary = {0};
    char *fatal = NULL;
    int dial_rc = io->dial(user, url, true, true, ctx, dial_timeout_ns, &handle, &ordinary, &fatal);
    bool live = false;
    int rc = after_dial(handle, dial_rc, &ordinary, &fatal, result, password, &live, error);
    if (!live) return rc;
    rc = io->bind(user, handle, ctx, username, password, &ordinary, &fatal);
    if (rc != 0) {
        io->close(user, handle);
        release_call(&ordinary, &fatal);
        return ldap_fail(error, "LDAP bind failed");
    }
    io->close(user, handle);
    int classified = classify(result, &ordinary, password, error);
    release_call(&ordinary, &fatal);
    return classified;
}

/* Route on the projected ldap: or ldaps: prefix, never on ://. */
static int verify_url(const br_ldap_state *state, const br_scan_ctx *ctx, br_slice url,
                      br_slice username, br_slice password, br_result *result, char **error)
{
    if (url.len >= 6 && url.data && !memcmp(url.data, "ldaps:", 6))
        return verify_ldaps(state, ctx, url, username, password, result, error);
    if (url.len >= 5 && url.data && !memcmp(url.data, "ldap:", 5))
        return verify_ldap(state, ctx, url, username, password, result, error);
    return unknown_scheme(url, error);
}

typedef struct {
    br_slice input;
    br_captures *values;
    char *error;
} uri_collect;

static int collect_uri(void *user, const br_span *groups, size_t ngroups)
{
    uri_collect *collect = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > collect->input.len)
        return ldap_fail(&collect->error, "invalid LDAP URI capture");
    br_slice value = {collect->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    return br_captures_push(collect->values, value, false, &collect->error);
}

typedef struct { br_bytes url, username, password; } iad_item;
typedef struct {
    br_slice input;
    iad_item *items;
    size_t len, cap;
    char *error;
} iad_collect;

static void iad_clear(iad_collect *collect)
{
    for (size_t i = 0; i < collect->len; ++i) {
        free(collect->items[i].url.data);
        free(collect->items[i].username.data);
        free(collect->items[i].password.data);
    }
    free(collect->items);
    collect->items = NULL;
    collect->len = collect->cap = 0;
}

static int copy_span(br_slice input, br_span span, br_bytes *out, char **error)
{
    if (span.begin == SIZE_MAX || span.end <= span.begin || span.end > input.len)
        return ldap_fail(error, "invalid LDAP capture");
    size_t n = span.end - span.begin;
    unsigned char *data = malloc(n + 1);
    if (!data) return ldap_fail(error, "cannot copy LDAP capture");
    memcpy(data, input.data + span.begin, n);
    data[n] = '\0';
    *out = (br_bytes){data, n};
    return 0;
}

static int collect_iad(void *user, const br_span *groups, size_t ngroups)
{
    iad_collect *collect = user;
    if (ngroups < 4) return ldap_fail(&collect->error, "invalid LDAP IAD capture");
    if (collect->len == collect->cap) {
        size_t cap = collect->cap ? collect->cap * 2 : 4;
        if (cap < collect->cap || cap > SIZE_MAX / sizeof(*collect->items))
            return ldap_fail(&collect->error, "too many LDAP IAD matches");
        iad_item *items = realloc(collect->items, cap * sizeof(*items));
        if (!items) return ldap_fail(&collect->error, "cannot allocate LDAP IAD matches");
        collect->items = items;
        collect->cap = cap;
    }
    iad_item item = {0};
    if (copy_span(collect->input, groups[1], &item.url, &collect->error) ||
        copy_span(collect->input, groups[2], &item.username, &collect->error) ||
        copy_span(collect->input, groups[3], &item.password, &collect->error)) {
        free(item.url.data);
        free(item.username.data);
        free(item.password.data);
        return -1;
    }
    collect->items[collect->len++] = item;
    return 0;
}

static int each_regex(const br_regex *regex, br_slice input, br_match_fn fn, void *user,
                      char **owned, char **error)
{
    char *regex_error = NULL;
    int rc = br_regex_each(regex, input, fn, user, &regex_error);
    if (owned && *owned) {
        free(regex_error);
        regex_error = *owned;
        *owned = NULL;
    }
    if (error && !*error) *error = regex_error;
    else free(regex_error);
    return rc ? -1 : 0;
}

static int project_uri(br_slice uri, br_bytes *out, bool *accepted, char **error)
{
    *out = (br_bytes){0};
    *accepted = false;
    char *fatal = NULL;
    int rc = br_ldap_url_string(uri, out, accepted, &fatal);
    if (rc != 0) {
        free(out->data);
        *out = (br_bytes){0};
        *accepted = false;
        if (!fatal) return ldap_fail(error, "LDAP URL projection failed");
        if (error) *error = fatal;
        else free(fatal);
        return -1;
    }
    free(fatal);
    return 0;
}

static int emit(const br_ldap_state *state, const br_scan_ctx *ctx, bool verify,
                br_slice url, br_slice username, br_slice password,
                br_results *out, char **error)
{
    br_result result = {0};
    if (make_finding(&result, url, username, password) != 0) {
        br_result_clear(&result);
        return ldap_fail(error, "cannot create LDAP result");
    }
    int rc = 0;
    if (verify) rc = verify_url(state, ctx, url, username, password, &result, error);
    if (!rc && br_results_push(out, &result) != 0)
        rc = ldap_fail(error, "cannot append LDAP result");
    br_result_clear(&result);
    return rc;
}

static int ldap_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const br_ldap_state *state = detector ? detector->state : NULL;
    if (!state || !state->uri || !state->username || !state->password || !state->iad ||
        !out || (!input.data && input.len))
        return ldap_fail(error, "invalid or uninitialized LDAP scan");
    size_t original_len = out->len;
    br_captures uris = {0};
    uri_collect uri_user = {.input = input, .values = &uris};
    char *owned = NULL;
    int rc = each_regex(state->uri, input, collect_uri, &uri_user, &uri_user.error, &owned);
    if (!rc && owned) rc = -1;
    if (rc && !owned) owned = strdup("cannot collect LDAP matches");

    for (size_t u = 0; !rc && u < uris.len; ++u) {
        br_bytes projected = {0};
        bool accepted = false;
        rc = project_uri(br_captures_at(&uris, u), &projected, &accepted, &owned);
        if (rc || !accepted) {
            free(projected.data);
            if (rc) break;
            continue;
        }
        br_captures usernames = {0};
        rc = br_captures_find(state->username, input, &usernames, false, &owned);
        if (!rc && owned) rc = -1;
        if (rc && !owned) owned = strdup("cannot collect LDAP matches");
        if (!rc && usernames.len) {
            br_slice url = {projected.data, projected.len};
            for (size_t i = 0; !rc && i < usernames.len; ++i) {
                br_captures passwords = {0};
                rc = br_captures_find(state->password, input, &passwords, false, &owned);
                if (!rc && owned) rc = -1;
                if (rc && !owned) owned = strdup("cannot collect LDAP matches");
                for (size_t j = 0; !rc && j < passwords.len; ++j)
                    rc = emit(state, ctx, verify, url, br_captures_at(&usernames, i),
                              br_captures_at(&passwords, j), out, &owned);
                br_captures_clear(&passwords);
            }
        }
        br_captures_clear(&usernames);
        free(projected.data);
    }

    iad_collect iads = {.input = input};
    if (!rc) {
        rc = each_regex(state->iad, input, collect_iad, &iads, &iads.error, &owned);
        if (!rc && owned) rc = -1;
        if (rc && !owned) owned = strdup("cannot collect LDAP matches");
    }
    for (size_t i = 0; !rc && i < iads.len; ++i) {
        br_bytes projected = {0};
        bool accepted = false;
        br_slice raw_url = {iads.items[i].url.data, iads.items[i].url.len};
        rc = project_uri(raw_url, &projected, &accepted, &owned);
        if (rc) {
            free(projected.data);
            break;
        }
        if (accepted) {
            rc = emit(state, ctx, verify, (br_slice){projected.data, projected.len},
                      (br_slice){iads.items[i].username.data, iads.items[i].username.len},
                      (br_slice){iads.items[i].password.data, iads.items[i].password.len},
                      out, &owned);
        }
        free(projected.data);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&uris);
    iad_clear(&iads);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const ldap_keywords[] = {"ldaps://", "ldap://"};
static br_detector ldap_detector = {
    .type = 901,
    .version = 0,
    .name = "LDAP",
    .custom_name = "",
    .description = "LDAP (Lightweight Directory Access Protocol) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network.",
    .keywords = ldap_keywords,
    .nkeywords = 2,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = 1024,
    .state = &ldap_state,
    .scan = ldap_scan,
};

int br_ldap_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ldap_fail(error, "invalid LDAP detector output");
    *out = NULL;
    if (!ldap_state.uri || !ldap_state.username || !ldap_state.password || !ldap_state.iad) {
        int rc = 0;
        if (!ldap_state.uri) rc = br_regex_compile(uri_pattern, &ldap_state.uri, error);
        if (!rc && !ldap_state.username)
            rc = br_regex_compile_prefixed(username_keywords, 2, username_suffix, &ldap_state.username, error);
        if (!rc && !ldap_state.password)
            rc = br_regex_compile_prefixed(password_keywords, 1, password_suffix, &ldap_state.password, error);
        if (!rc && !ldap_state.iad) rc = br_regex_compile(iad_pattern, &ldap_state.iad, error);
        if (rc) {
            br_regex_free(ldap_state.uri);
            br_regex_free(ldap_state.username);
            br_regex_free(ldap_state.password);
            br_regex_free(ldap_state.iad);
            ldap_state.uri = ldap_state.username = ldap_state.password = ldap_state.iad = NULL;
            return -1;
        }
    }
    *out = &ldap_detector;
    return 0;
}
