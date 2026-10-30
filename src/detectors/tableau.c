/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tableau/tableau.go. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "json.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *name, *secret, *url; } tableau_patterns;

static const char cred_type[] =
    "struct { Site struct { ID string \"json:\\\"id\\\"\"; ContentURL string \"json:\\\"contentUrl\\\"\" } "
    "\"json:\\\"site\\\"\"; User struct { ID string \"json:\\\"id\\\"\" } \"json:\\\"user\\\"\"; Token string \"json:\\\"token\\\"\" }";
static const char site_type[] =
    "struct { ID string \"json:\\\"id\\\"\"; ContentURL string \"json:\\\"contentUrl\\\"\" }";
static const char user_type[] = "struct { ID string \"json:\\\"id\\\"\" }";
static const char *const name_keywords[] = {"pat", "token", "name", "tableau"};
static const char *const fp_terms[] = {"com"};

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_name(br_regex **out, char **error)
{
    char *prefix = NULL;
    const char rest[] = "([a-zA-Z][a-zA-Z0-9_-]{2,50})";
    if (br_prefix_regex(name_keywords, 4, &prefix) != 0)
        return fail(error, "cannot allocate Tableau name prefix");
    size_t first = strlen(prefix);
    char *pattern = malloc(first + sizeof(rest));
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate Tableau name pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, sizeof(rest));
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int add_part(br_json *obj, const char *name, const void *data, size_t len)
{
    if (len > 2147483647u) return -1;
    br_json *part = json_object_new_string_len(data ? data : "", (int)len);
    if (!part || json_object_object_add(obj, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int put_text(br_json *obj, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value ? value : "");
    if (!part || json_object_object_add(obj, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int quote_ascii(br_slice text, char **out, char **fatal)
{
    size_t cap = text.len * 4 + 3;
    char *quoted = malloc(cap ? cap : 1);
    if (!quoted) return fail(fatal, "cannot quote Tableau URL diagnostic");
    size_t n = 0;
    quoted[n++] = '"';
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c >= 0x80) {
            free(quoted);
            return fail(fatal, "unsupported: non-ASCII Tableau URL diagnostic");
        }
        if (c == '"' || c == '\\') {
            quoted[n++] = '\\';
            quoted[n++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            quoted[n++] = '\\';
            quoted[n++] = c == '\n' ? 'n' : c == '\r' ? 'r' : 't';
        } else if (c < 0x20) {
            n += (size_t)sprintf(quoted + n, "\\x%02x", c);
        } else quoted[n++] = (char)c;
    }
    quoted[n++] = '"';
    quoted[n] = '\0';
    *out = quoted;
    return 0;
}

static int request_cause(const char *url, const br_go_url_error *rejection, char **cause, char **fatal)
{
    char *quoted_url = NULL, *inner = NULL;
    if (quote_ascii((br_slice){(const unsigned char *)url, strlen(url)}, &quoted_url, fatal) != 0)
        return -1;
    const char *fixed = NULL;
    switch (rejection->kind) {
    case BR_GO_URL_CONTROL: fixed = "net/url: invalid control character in URL"; break;
    case BR_GO_URL_SCHEME: fixed = "missing protocol scheme"; break;
    case BR_GO_URL_COLON: fixed = "first path segment in URL cannot contain colon"; break;
    case BR_GO_URL_BAD_USER: fixed = "net/url: invalid userinfo"; break;
    case BR_GO_URL_BRACKET: fixed = "missing ']' in host"; break;
    case BR_GO_URL_IP_LITERAL: fixed = "invalid IP-literal"; break;
    default: break;
    }
    if (fixed) inner = strdup(fixed);
    else if (rejection->kind == BR_GO_URL_ESCAPE || rejection->kind == BR_GO_URL_HOST_CHAR ||
             rejection->kind == BR_GO_URL_PORT) {
        char *detail = NULL;
        const char *fmt = rejection->kind == BR_GO_URL_ESCAPE ? "invalid URL escape %s" :
                          rejection->kind == BR_GO_URL_HOST_CHAR ? "invalid character %s in host name" :
                          "invalid port %s after host";
        if (quote_ascii(rejection->detail, &detail, fatal) != 0) {
            free(quoted_url);
            return -1;
        }
        size_t len = strlen(fmt) + strlen(detail) + 1;
        inner = malloc(len);
        if (inner) snprintf(inner, len, fmt, detail);
        free(detail);
    } else {
        free(quoted_url);
        return fail(fatal, "unsupported: Tableau URL parse error text");
    }
    if (!inner) {
        free(quoted_url);
        return fail(fatal, "cannot format Tableau URL error");
    }
    size_t len = strlen(quoted_url) + strlen(inner) + sizeof("failed to create request: parse : ");
    char *message = malloc(len);
    if (!message) {
        free(inner);
        free(quoted_url);
        return fail(fatal, "cannot format Tableau URL error");
    }
    snprintf(message, len, "failed to create request: parse %s: %s", quoted_url, inner);
    free(inner);
    free(quoted_url);
    *cause = message;
    return 0;
}

typedef struct {
    bool ordinary;
    char *cause;
} tableau_types;

/* First type error sticks, even when its cause is NULL. Later helpers still run. */
static int note_type(tableau_types *types, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) {
        free(next);
        return rc;
    }
    if (!types->ordinary) {
        types->ordinary = true;
        types->cause = next;
    } else free(next);
    return 0;
}

static int expect_text(tableau_types *types, br_json *value, const char *path)
{
    if (!value || json_object_is_type(value, json_type_null) ||
        json_object_is_type(value, json_type_string))
        return 0;
    return note_type(types, value, path, "string");
}

static int site_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    tableau_types *types = user;
    if (br_json_field_name(name, "id")) return expect_text(types, value, ".credentials.site.id");
    if (br_json_field_name(name, "contenturl"))
        return expect_text(types, value, ".credentials.site.contentUrl");
    return 0;
}

static int user_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (!br_json_field_name(name, "id")) return 0;
    return expect_text(user, value, ".credentials.user.id");
}

static int credential_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    tableau_types *types = user;
    if (br_json_field_name(name, "site")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_object))
            return note_type(types, value, ".credentials.site", site_type);
        return br_json_each_member(encoded, site_member, types);
    }
    if (br_json_field_name(name, "user")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_object))
            return note_type(types, value, ".credentials.user", user_type);
        return br_json_each_member(encoded, user_member, types);
    }
    if (br_json_field_name(name, "token")) return expect_text(types, value, ".credentials.token");
    return 0;
}

static int auth_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    tableau_types *types = user;
    if (!br_json_field_name(name, "credentials")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return note_type(types, value, "TableauAuthResponse.credentials", cred_type);
    return br_json_each_member(encoded, credential_member, types);
}

/* 0 accepted, 1 ordinary type cause, -1 fatal. Walk original order, including duplicates. */
static int response_types(br_slice body, br_json *doc, char **cause)
{
    if (!doc || json_object_is_type(doc, json_type_null)) return 0;
    tableau_types types = {0};
    int rc = 0;
    if (!json_object_is_type(doc, json_type_object))
        rc = note_type(&types, doc, NULL, "tableau.TableauAuthResponse");
    else if (body.data && body.len)
        rc = br_json_each_member(body, auth_member, &types);
    if (rc != 0) {
        free(types.cause);
        return -1;
    }
    if (types.ordinary) {
        *cause = types.cause;
        return 1;
    }
    return 0;
}

static int copy_extra(br_result *result, const char *url, const char *endpoint, bool network)
{
    if (put_text(result->extra_data, "verification_endpoint", url) != 0 ||
        put_text(result->extra_data, "verification_method", "tableau_pat_auth") != 0 ||
        put_text(result->extra_data, "tableau_endpoint", endpoint) != 0)
        return -1;
    if (network && put_text(result->extra_data, "network_error", "true") != 0) return -1;
    return 0;
}

static int set_error(br_result *result, const char *cause, br_slice name, br_slice secret,
                     const char *endpoint)
{
    br_slice secrets[] = {name, secret, {(const unsigned char *)endpoint, strlen(endpoint)}};
    return br_result_set_verification_error(result, cause, secrets, 3) == 0 ? 0 : -1;
}

static int tableau_verify(const br_scan_ctx *ctx, br_result *result, br_slice name, br_slice secret,
                          const char *endpoint, char **error)
{
    size_t elen = strlen(endpoint);
    char *url = malloc(elen + sizeof("https:///api/3.26/auth/signin"));
    char body[256];
    if (!url) return fail(error, "cannot allocate Tableau verification URL");
    memcpy(url, "https://", 8);
    memcpy(url + 8, endpoint, elen);
    memcpy(url + 8 + elen, "/api/3.26/auth/signin", sizeof("/api/3.26/auth/signin"));
    int body_n = snprintf(body, sizeof(body),
                          "{\"credentials\":{\"personalAccessTokenName\":\"%.*s\","
                          "\"personalAccessTokenSecret\":\"%.*s\",\"site\":{}}}",
                          (int)name.len, name.data, (int)secret.len, secret.data);
    if (body_n < 0 || (size_t)body_n >= sizeof(body)) {
        free(url);
        return fail(error, "cannot build Tableau auth body");
    }
    /* Marshal and URL exist before NewRequestWithContext. Nil context wins over parse. */
    if (!ctx) {
        int rc = set_error(result, "failed to create request: net/http: nil Context", name, secret, endpoint);
        free(url);
        return rc == 0 ? 0 : fail(error, "cannot set Tableau verification error");
    }
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    int parsed = br_go_url_parse((br_slice){(const unsigned char *)url, strlen(url)}, &parts, &rejection, error);
    br_go_url_clear(&parts);
    if (parsed != 0) {
        free(url);
        return -1;
    }
    if (rejection.kind != BR_GO_URL_OK) {
        char *cause = NULL;
        int rc = request_cause(url, &rejection, &cause, error);
        free(url);
        if (rc != 0) {
            free(cause);
            return -1;
        }
        rc = set_error(result, cause, name, secret, endpoint);
        free(cause);
        return rc == 0 ? 0 : fail(error, "cannot set Tableau verification error");
    }
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Accept", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, (size_t)body_n},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        if (send_error && (strstr(send_error, "no such host") || strstr(send_error, "dial tcp") ||
                           strstr(send_error, "connection refused"))) {
            rc = copy_extra(result, url, endpoint, true);
            /* Source returns a nil error, then the caller still reaches the setter. */
            if (!rc && set_error(result, NULL, name, secret, endpoint))
                rc = fail(error, "cannot set Tableau verification error");
        } else {
            const char *detail = send_error ? send_error : "";
            char *cause = malloc(strlen(detail) + sizeof("request failed: "));
            if (!cause) rc = fail(error, "cannot format Tableau request failure");
            else {
                sprintf(cause, "request failed: %s", detail);
                rc = set_error(result, cause, name, secret, endpoint);
                free(cause);
                if (rc) rc = fail(error, "cannot set Tableau verification error");
            }
        }
    } else if (response.body_error) {
        char *cause = malloc(strlen(response.body_error) + sizeof("failed to read response body: "));
        if (!cause) rc = fail(error, "cannot format Tableau body error");
        else {
            sprintf(cause, "failed to read response body: %s", response.body_error);
            rc = set_error(result, cause, name, secret, endpoint);
            free(cause);
            if (rc) rc = fail(error, "cannot set Tableau verification error");
        }
    } else if (response.status == 200) {
        br_json *doc = NULL;
        char *decode = NULL;
        int decoded = br_json_document(response.body, &doc, &decode);
        /* Only document +1 is an ordinary unmarshal error. +2 must not verify. */
        if (decoded < 0 || decoded > 1) rc = fail(error, "cannot decode Tableau auth response");
        else result->verified = true;
        if (!rc && decoded == 0) {
            int typed = response_types(response.body, doc, &decode);
            if (typed < 0) rc = fail(error, "cannot classify Tableau auth response");
        }
        if (!rc) rc = copy_extra(result, url, endpoint, false);
        if (!rc && set_error(result, decode, name, secret, endpoint))
            rc = fail(error, "cannot set Tableau verification error");
        json_object_put(doc);
        free(decode);
    } else if (response.status == 401 || response.status == 400 || response.status == 403) {
        rc = copy_extra(result, url, endpoint, false);
        if (!rc && set_error(result, NULL, name, secret, endpoint))
            rc = fail(error, "cannot set Tableau verification error");
    } else {
        char status_error[64];
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        rc = copy_extra(result, url, endpoint, false);
        if (!rc) rc = set_error(result, status_error, name, secret, endpoint);
        if (rc) rc = fail(error, "cannot set Tableau verification error");
    }
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc;
}

static int tableau_finding(br_result *result, br_slice name, br_slice secret, const char *endpoint)
{
    size_t elen = strlen(endpoint);
    if (name.len > SIZE_MAX - secret.len || elen > SIZE_MAX - name.len - secret.len - 2) return -1;
    result->detector_type = 1034;
    result->raw.len = name.len;
    result->raw_v2.len = name.len + secret.len + elen + 2;
    result->raw.data = malloc(name.len ? name.len : 1);
    result->raw_v2.data = malloc(result->raw_v2.len ? result->raw_v2.len : 1);
    result->secret_parts = json_object_new_object();
    result->extra_data = json_object_new_object();
    if (!result->raw.data || !result->raw_v2.data || !result->secret_parts || !result->extra_data) {
        br_result_clear(result);
        return -1;
    }
    if (name.len) memcpy(result->raw.data, name.data, name.len);
    unsigned char *out = result->raw_v2.data;
    if (name.len) memcpy(out, name.data, name.len);
    out += name.len;
    *out++ = ':';
    if (secret.len) memcpy(out, secret.data, secret.len);
    out += secret.len;
    *out++ = ':';
    if (elen) memcpy(out, endpoint, elen);
    if (add_part(result->secret_parts, "token_name", name.data, name.len) != 0 ||
        add_part(result->secret_parts, "pat_secret", secret.data, secret.len) != 0 ||
        add_part(result->secret_parts, "endpoint", endpoint, elen) != 0) {
        br_result_clear(result);
        return -1;
    }
    return 0;
}

static int keep_name(br_slice name, bool *keep, char **error)
{
    char *reason = NULL;
    bool fp = br_known_false_positive(name, fp_terms, 1, false, &reason);
    if (reason && !strncmp(reason, "unsupported:", 12)) {
        free(reason);
        return fail(error, "unsupported Tableau false-positive check");
    }
    free(reason);
    *keep = !fp;
    return 0;
}

static int scan_tableau(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TableauPersonalAccessToken scan");
    const tableau_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures names = {0}, kept = {0}, secrets = {0}, found = {0};
    br_endpoint_list collected = {0}, endpoints = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->name, input, &names, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    for (size_t i = 0; !rc && i < names.len; ++i) {
        bool keep = false;
        br_slice name = br_captures_at(&names, i);
        rc = keep_name(name, &keep, &owned_error);
        if (!rc && keep) rc = br_captures_push(&kept, name, false, &owned_error);
    }
    if (!rc && kept.len && secrets.len) {
        rc = br_captures_find(patterns->url, input, &found, false, &owned_error);
        if (!rc) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, detector->cloud_endpoint,
                                           &found, &collected, &owned_error);
    }
    /* Trim only an https:// prefix, then collapse like the source map. First-seen is one map order. */
    for (size_t i = 0; !rc && i < collected.len; ++i) {
        const char *endpoint = collected.items[i];
        if (!strncmp(endpoint, "https://", 8)) endpoint += 8;
        rc = br_endpoint_list_push(&endpoints, endpoint, true, &owned_error);
    }
    for (size_t n = 0; !rc && n < kept.len; ++n) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            for (size_t e = 0; !rc && e < endpoints.len; ++e) {
                br_result result = {0};
                br_slice name = br_captures_at(&kept, n);
                br_slice secret = br_captures_at(&secrets, s);
                if (tableau_finding(&result, name, secret, endpoints.items[e]) != 0)
                    rc = fail(&owned_error, "cannot create TableauPersonalAccessToken result");
                if (!rc && verify)
                    rc = tableau_verify(ctx, &result, name, secret, endpoints.items[e], &owned_error);
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned_error, "cannot append TableauPersonalAccessToken result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_endpoint_list_clear(&endpoints);
    br_endpoint_list_clear(&collected);
    br_captures_clear(&found);
    br_captures_clear(&secrets);
    br_captures_clear(&kept);
    br_captures_clear(&names);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static tableau_patterns patterns;
static const char *const keywords[] = {"tableau", "online.tableau.com"};
static br_detector tableau = {
    .type = 1034, .version = 0, .name = "TableauPersonalAccessToken", .custom_name = "",
    .description = "Tableau is a data visualization and business intelligence platform. Personal Access Tokens (PATs) provide programmatic access to Tableau Server/Online APIs and can be used to authenticate applications and automate workflows.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_tableau,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};

int br_tableau_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TableauPersonalAccessToken detector output");
    *out = NULL;
    if (!patterns.name && compile_name(&patterns.name, error) != 0) return -1;
    if (!patterns.secret &&
        br_regex_compile("\\b([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\\b", &patterns.secret, error) != 0)
        return -1;
    if (!patterns.url &&
        br_regex_compile("\\b([a-zA-Z0-9\\-]+\\.online\\.tableau\\.com)\\b", &patterns.url, error) != 0)
        return -1;
    *out = &tableau;
    return 0;
}
