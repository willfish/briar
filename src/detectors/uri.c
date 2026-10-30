/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * URI, from pinned TruffleHog pkg/detectors/uri/uri.go.
 * Credential URLs are deduped by the full match. Raw omits the path; RawV2
 * keeps it. Verification uses the public-address client, trims one trailing
 * slash, then compares a credentialed 2xx with a later 400-428 challenge.
 * httpbin.org and httpwatch.com matches are skipped. A process-wide cache
 * drops later verification of a hostname whose lookup reported no such host.
 */
#include "detectors.h"
#include "findings.h"
#include "../go_url.h"

#include <ctype.h>
#include <json-c/json.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char pattern[] =
    "\\bhttps?://[\\w!#$%&()*+,\\-./;<=>?@[\\\\\\]^_{|}~]{0,50}:"
    "([\\w!#$%&()*+,\\-./:;<=>?[\\\\\\]^_{|}~]{3,50})"
    "@[a-zA-Z0-9.-]+(?:\\.[a-zA-Z]{2,})?(?::\\d{1,5})?[\\w/]+\\b";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static char **cache_hosts;
static size_t cache_len, cache_cap;
static pthread_mutex_t cache_mu = PTHREAD_MUTEX_INITIALIZER;

static bool cache_has(const char *host)
{
    bool found = false;
    pthread_mutex_lock(&cache_mu);
    for (size_t i = 0; i < cache_len; ++i)
        if (!strcmp(cache_hosts[i], host)) { found = true; break; }
    pthread_mutex_unlock(&cache_mu);
    return found;
}

static int cache_add(const char *host, char **error)
{
    pthread_mutex_lock(&cache_mu);
    for (size_t i = 0; i < cache_len; ++i)
        if (!strcmp(cache_hosts[i], host)) { pthread_mutex_unlock(&cache_mu); return 0; }
    if (cache_len == cache_cap) {
        size_t cap = cache_cap ? cache_cap * 2 : 8;
        char **hosts = realloc(cache_hosts, cap * sizeof(*hosts));
        if (!hosts) { pthread_mutex_unlock(&cache_mu); return fail(error, "cannot cache URI host"); }
        cache_hosts = hosts;
        cache_cap = cap;
    }
    if (!(cache_hosts[cache_len] = strdup(host))) {
        pthread_mutex_unlock(&cache_mu);
        return fail(error, "cannot cache URI host");
    }
    ++cache_len;
    pthread_mutex_unlock(&cache_mu);
    return 0;
}

static bool cutset_only(const char *s, const char *cut)
{
    if (!s || !*s) return false;
    for (; *s; ++s)
        if (!strchr(cut, *s)) return false;
    return true;
}

static int append_mem(char **buf, size_t *len, size_t *cap, const void *data, size_t n)
{
    if (*len + n + 1 < *len) return -1;
    if (*len + n + 1 > *cap) {
        size_t next = *cap ? *cap : 64;
        while (next < *len + n + 1) {
            if (next > SIZE_MAX / 2) return -1;
            next *= 2;
        }
        char *grown = realloc(*buf, next);
        if (!grown) return -1;
        *buf = grown;
        *cap = next;
    }
    if (n) memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = 0;
    return 0;
}

static int append_str(char **buf, size_t *len, size_t *cap, const char *s)
{
    return append_mem(buf, len, cap, s, strlen(s));
}

static bool userinfo_escape(unsigned char c)
{
    if (isalnum(c) || strchr("-_.~", c) || strchr("$&+,;=", c)) return false;
    return true;
}

static int append_userinfo(char **buf, size_t *len, size_t *cap, br_slice s)
{
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (!userinfo_escape(c)) {
            if (append_mem(buf, len, cap, &c, 1) != 0) return -1;
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            if (append_str(buf, len, cap, hex) != 0) return -1;
        }
    }
    return 0;
}

static int build_url(char **out, const char *scheme, bool with_user, br_slice user, br_slice password,
                     br_slice host, br_slice path)
{
    char *buf = NULL;
    size_t len = 0, cap = 0;
    if (append_str(&buf, &len, &cap, scheme) || append_str(&buf, &len, &cap, "://") ||
        (with_user && (append_userinfo(&buf, &len, &cap, user) || append_str(&buf, &len, &cap, ":") ||
                       append_userinfo(&buf, &len, &cap, password) || append_str(&buf, &len, &cap, "@"))) ||
        append_mem(&buf, &len, &cap, host.data, host.len) ||
        append_mem(&buf, &len, &cap, path.data, path.len)) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

static char *replace_encoded_stars(char *text)
{
    char *src = text, *dst = text;
    while (*src) {
        if (!strncmp(src, "%2A", 3)) { *dst++ = '*'; src += 3; }
        else *dst++ = *src++;
    }
    *dst = 0;
    return text;
}

static void hostname_of(br_slice host, char *out, size_t cap)
{
    if (host.len && host.data[0] == '[') {
        size_t end = 1;
        while (end < host.len && host.data[end] != ']') ++end;
        size_t n = end > 1 ? end - 1 : 0;
        if (n >= cap) n = cap - 1;
        memcpy(out, host.data + 1, n);
        out[n] = 0;
        return;
    }
    size_t n = host.len;
    size_t colon = n;
    for (size_t i = 0; i < host.len; ++i)
        if (host.data[i] == ':') colon = i;
    if (colon != host.len) {
        bool port = colon + 1 < host.len;
        for (size_t i = colon + 1; port && i < host.len; ++i)
            if (host.data[i] < '0' || host.data[i] > '9') port = false;
        if (port) n = colon;
    }
    if (n >= cap) n = cap - 1;
    memcpy(out, host.data, n);
    out[n] = 0;
}

static bool header_present(const br_http_response *response, const char *name)
{
    for (size_t i = 0; i < response->nheaders; ++i)
        if (response->headers[i].name && !strcasecmp(response->headers[i].name, name) &&
            response->headers[i].value && response->headers[i].value[0])
            return true;
    return false;
}

static int verify(const br_scan_ctx *ctx, const char *credentialed, const char *plain, const char *password,
                  const char *hostname, br_result *result, char **error)
{
    br_slice secret = {(const unsigned char *)password, strlen(password)};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot store URI verification error");
        return 0;
    }
    const br_http_request first = {
        .method = "GET", .url = credentialed, .timeout_ms = 10000,
        .detector_type = 17, .profile = BR_HTTP_DETECTOR_PUBLIC,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    bool not_found = false;
    int rc = 0;
    if (br_http_send(ctx, &first, &response, &transport_error) != 0) {
        cause = transport_error; /* NULL diagnostic stays NULL. */
        not_found = cause && strstr(cause, "no such host");
    } else if (response.status >= 200 && response.status <= 299) {
        br_http_release(ctx, &response);
        nanosleep(&(struct timespec){.tv_nsec = 10000000}, NULL);
        const br_http_request second = {
            .method = "GET", .url = plain, .timeout_ms = 10000,
            .detector_type = 17, .profile = BR_HTTP_DETECTOR_PUBLIC,
        };
        if (br_http_send(ctx, &second, &response, &transport_error) != 0) {
            cause = transport_error; /* NULL diagnostic stays NULL. */
            not_found = cause && strstr(cause, "no such host");
        } else if (response.status >= 400 && response.status < 429 && header_present(&response, "WWW-Authenticate"))
            result->verified = true;
    }
    if (not_found && cache_add(hostname, error) != 0) rc = -1;
    if (!rc && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "cannot store URI verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int add_part(br_json *object, const char *name, const char *value, char **error)
{
    br_json *item = json_object_new_string(value);
    if (!item || json_object_object_add(object, name, item) != 0) {
        json_object_put(item);
        return fail(error, "cannot create URI secret parts");
    }
    return 0;
}

static int one(const br_scan_ctx *ctx, bool verify_requested, const char *uri, const char *password,
               br_results *out, char **error)
{
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *parse_error = NULL;
    int parsed = br_go_url_parse((br_slice){(const unsigned char *)uri, strlen(uri)}, &parts, &rejection, &parse_error);
    if (parsed != 0) {
        if (error && !*error) *error = parse_error;
        else free(parse_error);
        return -1;
    }
    if (rejection.kind != BR_GO_URL_OK || !parts.has_password || !parts.raw_password.len) {
        br_go_url_clear(&parts);
        return 1;
    }
    const char *scheme = !strncmp(uri, "https://", 8) ? "https" : "http";
    char *with_path = NULL, *without_path = NULL, *redacted = NULL;
    br_slice empty = {0};
    br_slice stars = {(const unsigned char *)"********", 8};
    int rc = 0;
    if (build_url(&with_path, scheme, true, parts.raw_user, parts.raw_password, parts.host, parts.raw_path) ||
        build_url(&without_path, scheme, true, parts.raw_user, parts.raw_password, parts.host, empty) ||
        build_url(&redacted, scheme, true, parts.raw_user, stars, parts.host, parts.raw_path))
        rc = fail(error, "cannot format URI result");
    if (!rc) replace_encoded_stars(redacted);
    br_bytes user = {0};
    bool user_valid = false;
    if (!rc && br_go_url_decode(parts.raw_user, false, &user, &user_valid, error) != 0) rc = -1;
    if (!rc && !user_valid) { br_go_url_clear(&parts); free(with_path); free(without_path); free(redacted); free(user.data); return 1; }
    char host[256], name[256];
    hostname_of(parts.host, host, sizeof(host));
    if (!rc && (parts.host.len >= sizeof(name) || user.len >= sizeof(name)))
        rc = fail(error, "cannot format URI secret parts");
    if (!rc) {
        memcpy(name, parts.host.data, parts.host.len);
        name[parts.host.len] = 0;
    }
    br_result result = {0};
    if (!rc) {
        result.detector_name = strdup("URI");
        result.detector_type = 17;
        result.raw = (br_bytes){(unsigned char *)without_path, strlen(without_path)};
        result.raw_v2 = (br_bytes){(unsigned char *)with_path, strlen(with_path)};
        result.redacted = redacted;
        result.secret_parts = json_object_new_object();
        without_path = with_path = redacted = NULL;
        if (!result.detector_name || !result.secret_parts ||
            add_part(result.secret_parts, "host", name, error) ||
            add_part(result.secret_parts, "username", user.len ? (const char *)user.data : "", error) ||
            add_part(result.secret_parts, "password", password, error))
            rc = fail(error, "cannot create URI finding");
    }
    char credentialed[768], plain[768];
    if (!rc && verify_requested) {
        if (cache_has(host)) {
            br_result_clear(&result);
            br_go_url_clear(&parts);
            free(user.data);
            free(with_path); free(without_path); free(redacted);
            return 1;
        }
        br_slice path = parts.raw_path;
        if (path.len && path.data[path.len - 1] == '/') path.len--;
        char *cred = NULL, *open = NULL;
        if (build_url(&cred, scheme, true, parts.raw_user, parts.raw_password, parts.host, path) ||
            build_url(&open, scheme, false, empty, empty, parts.host, path) ||
            strlen(cred) >= sizeof(credentialed) || strlen(open) >= sizeof(plain))
            rc = fail(error, "cannot format URI verification URL");
        else {
            memcpy(credentialed, cred, strlen(cred) + 1);
            memcpy(plain, open, strlen(open) + 1);
        }
        free(cred);
        free(open);
        if (!rc && verify(ctx, credentialed, plain, password, host, &result, error) != 0) rc = -1;
    }
    if (!rc && !result.verified && password[0] == '$') {
        br_result_clear(&result);
        rc = 1;
    } else if (!rc && br_results_push(out, &result) != 0)
        rc = fail(error, "cannot append URI finding");
    br_result_clear(&result);
    br_go_url_clear(&parts);
    free(user.data);
    free(with_path);
    free(without_path);
    free(redacted);
    return rc < 0 ? -1 : rc;
}

typedef struct {
    br_slice input;
    char **uris, **passwords;
    size_t len, cap;
    char **error;
} uri_matches;

static int collect(void *user, const br_span *groups, size_t ngroups)
{
    uri_matches *found = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end < groups[1].begin) return 0;
    size_t ulen = groups[0].end - groups[0].begin;
    size_t plen = groups[1].end - groups[1].begin;
    char *uri = malloc(ulen + 1), *password = malloc(plen + 1);
    if (!uri || !password) { free(uri); free(password); return fail(found->error, "cannot copy URI match"); }
    memcpy(uri, found->input.data + groups[0].begin, ulen);
    uri[ulen] = 0;
    memcpy(password, found->input.data + groups[1].begin, plen);
    password[plen] = 0;
    if (strstr(uri, "httpbin.org") || strstr(uri, "httpwatch.com") ||
        cutset_only(password, "*") || cutset_only(password, "%2A")) {
        free(uri);
        free(password);
        return 0;
    }
    for (size_t i = 0; i < found->len; ++i)
        if (!strcmp(found->uris[i], uri)) { free(uri); free(password); return 0; }
    if (found->len == found->cap) {
        size_t cap = found->cap ? found->cap * 2 : 8;
        char **uris = realloc(found->uris, cap * sizeof(*uris));
        if (!uris) { free(uri); free(password); return fail(found->error, "cannot store URI match"); }
        found->uris = uris;
        char **passwords = realloc(found->passwords, cap * sizeof(*passwords));
        if (!passwords) { free(uri); free(password); return fail(found->error, "cannot store URI match"); }
        found->passwords = passwords;
        found->cap = cap;
    }
    found->uris[found->len] = uri;
    found->passwords[found->len] = password;
    ++found->len;
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid URI scan arguments");
    size_t original = out->len;
    uri_matches found = {.input = input, .error = error};
    int rc = br_regex_each(detector->state, input, collect, &found, error);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        int outcome = one(ctx, verify_requested, found.uris[i], found.passwords[i], out, error);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < found.len; ++i) { free(found.uris[i]); free(found.passwords[i]); }
    free(found.uris);
    free(found.passwords);
    return rc ? -1 : 0;
}

static bool false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = NULL;
    return false;
}

static br_detector detector = {
    .name = "URI", .type = 17, .description =
        "This detector identifies URLs with embedded credentials, which can be used to access web resources without explicit user interaction.",
    .keywords = (const char *[]){"http://", "https://", NULL}, .nkeywords = 2, .scan = scan, .false_positive = false_positive,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_uri_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid URI detector output");
    *out = NULL;
    if (!detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile(pattern, &regex, error) != 0) return -1;
        detector.state = regex;
    }
    *out = &detector;
    return 0;
}
