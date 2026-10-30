/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/snowflake/snowflake.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"
#include "../go_unicode.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int snow_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool snow_cutset(unsigned char c)
{
    return c == '"' || c == '\'' || c == ' ' || c == ')' || c == ',' || c == ';';
}

static int snow_trim(br_slice value, br_slice *trimmed, char **error)
{
    size_t begin = 0, end;
    while (begin < value.len) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){value.data + begin, value.len - begin}, &rune);
        if (!width) return snow_fail(error, "cannot decode Snowflake capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        begin += width;
    }
    end = begin;
    for (size_t at = begin; at < value.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){value.data + at, value.len - at}, &rune);
        if (!width) return snow_fail(error, "cannot decode Snowflake capture");
        at += width;
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at;
    }
    while (begin < end && snow_cutset(value.data[begin])) ++begin;
    while (end > begin && snow_cutset(value.data[end - 1])) --end;
    *trimmed = (br_slice){value.data + begin, end - begin};
    return 0;
}

static int snow_password_ok(br_slice password, bool *ok, char **error)
{
    *ok = false;
    if (password.len < 8) return 0;
    bool lower = false, upper = false, number = false;
    for (size_t at = 0; at < password.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){password.data + at, password.len - at}, &rune);
        if (!width) return snow_fail(error, "cannot decode Snowflake password");
        unsigned props = br_go_unicode_properties(rune);
        lower = lower || (props & BR_GO_LOWER);
        upper = upper || (props & BR_GO_UPPER);
        number = number || (props & BR_GO_NUMBER);
        at += width;
        if (lower && upper && number) {
            *ok = true;
            return 0;
        }
    }
    return 0;
}

static int snow_append(char **buf, size_t *len, size_t *cap, const void *data, size_t n)
{
    if (n > SIZE_MAX - *len - 1) return -1;
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
    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static int snow_json_string(char **buf, size_t *len, size_t *cap, br_slice value)
{
    if (snow_append(buf, len, cap, "\"", 1) != 0) return -1;
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        const char *escape = NULL;
        char hex[8];
        if (c == '"') escape = "\\\"";
        else if (c == '\\') escape = "\\\\";
        else if (c == '\b') escape = "\\b";
        else if (c == '\f') escape = "\\f";
        else if (c == '\n') escape = "\\n";
        else if (c == '\r') escape = "\\r";
        else if (c == '\t') escape = "\\t";
        else if (c == '&') escape = "\\u0026";
        else if (c == '<') escape = "\\u003c";
        else if (c == '>') escape = "\\u003e";
        else if (c < 0x20) {
            snprintf(hex, sizeof(hex), "\\u%04x", c);
            escape = hex;
        }
        if (escape) {
            if (snow_append(buf, len, cap, escape, strlen(escape)) != 0) return -1;
        } else if (snow_append(buf, len, cap, &c, 1) != 0) return -1;
    }
    return snow_append(buf, len, cap, "\"", 1);
}

static int snow_body(br_slice username, br_slice password, br_slice account, char **body, size_t *len,
                     char **error)
{
    char *buf = NULL;
    size_t n = 0, cap = 0;
    const char *head = "{\"data\":{\"LOGIN_NAME\":";
    const char *mid = ",\"PASSWORD\":";
    const char *tail = ",\"ACCOUNT_NAME\":";
    int rc = snow_append(&buf, &n, &cap, head, strlen(head));
    if (rc == 0) rc = snow_json_string(&buf, &n, &cap, username);
    if (rc == 0) rc = snow_append(&buf, &n, &cap, mid, strlen(mid));
    if (rc == 0) rc = snow_json_string(&buf, &n, &cap, password);
    if (rc == 0) rc = snow_append(&buf, &n, &cap, tail, strlen(tail));
    if (rc == 0) rc = snow_json_string(&buf, &n, &cap, account);
    if (rc == 0) rc = snow_append(&buf, &n, &cap, "}}", 2);
    if (rc != 0) {
        free(buf);
        return snow_fail(error, "cannot marshal Snowflake login request");
    }
    *body = buf;
    *len = n;
    return 0;
}

static int snow_extra(br_result *result, br_slice account, br_slice username, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *account_value = json_object_new_string_len((const char *)account.data, (int)account.len);
    br_json *username_value = json_object_new_string_len((const char *)username.data, (int)username.len);
    if (!result->extra_data || !account_value || !username_value ||
        json_object_object_add(result->extra_data, "account", account_value) != 0 ||
        json_object_object_add(result->extra_data, "username", username_value) != 0) {
        json_object_put(account_value);
        json_object_put(username_value);
        return snow_fail(error, "cannot store Snowflake extra data");
    }
    return 0;
}

static int snow_cause(br_result *result, const char *cause, br_slice password, char **error)
{
    if (br_result_set_verification_error(result, cause, &password, 1) != 0)
        return snow_fail(error, "cannot store Snowflake verification error");
    return 0;
}

__attribute__((weak)) int br_snowflake_json_document(br_slice body, br_json **out, char **cause)
{
    return br_json_document(body, out, cause);
}

typedef struct {
    bool success;
    bool failed;
    char *cause;
} snow_login;

/* 0 is a completed diagnostic, even when cause is NULL. Every other code is fatal. */
__attribute__((weak)) int br_snowflake_type_cause(br_json *value, const char *field, const char *type,
                                                 char **cause)
{
    return br_json_type_cause(value, field, type, cause);
}

/* Nonzero, including +1, is fatal. The default reaches every success member. */
__attribute__((weak)) int br_snowflake_visit_success(br_json *value)
{
    (void)value;
    return 0;
}

static int snow_note(snow_login *login, br_json *value, const char *field, const char *type)
{
    char *cause = NULL;
    int typed = br_snowflake_type_cause(value, field, type, &cause);
    if (typed != 0) {
        free(cause);
        return typed;
    }
    if (!login->failed) {
        login->failed = true;
        login->cause = cause;
    } else free(cause);
    return 0;
}

static int snow_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (!br_json_field_name(name, "success")) return 0;
    int visited = br_snowflake_visit_success(value);
    if (visited != 0) return visited;
    snow_login *login = user;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (json_object_is_type(value, json_type_boolean)) {
        login->success = json_object_get_boolean(value);
        return 0;
    }
    return snow_note(login, value, "loginResponse.Success", "bool");
}

static int snow_success(br_slice body, bool *success, char **cause)
{
    br_json *root = NULL;
    int rc = br_snowflake_json_document(body, &root, cause);
    *success = false;
    if (rc == 1) {
        json_object_put(root);
        return 1; /* %w stays the inner cause; the caller formats %v when it exists. */
    }
    if (rc != 0) {
        json_object_put(root);
        return -1;
    }
    if (!root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        return 0;
    }
    snow_login login = {0};
    if (!json_object_is_type(root, json_type_object))
        rc = snow_note(&login, root, NULL, "snowflake.loginResponse");
    else rc = br_json_each_member(body, snow_member, &login);
    json_object_put(root);
    if (rc != 0) {
        free(login.cause);
        return -1;
    }
    if (login.failed) {
        *cause = login.cause;
        return 1;
    }
    *success = login.success;
    return 0;
}

static int snow_verify(const br_scan_ctx *ctx, br_slice account, br_slice username, br_slice password,
                       br_result *result, char **error)
{
    char *body = NULL;
    size_t body_len = 0;
    if (snow_body(username, password, account, &body, &body_len, error) != 0) return -1;
    static const char prefix[] = "https://";
    static const char suffix[] = ".snowflakecomputing.com/session/v1/login-request";
    int rc = 0;
    char *url = NULL;
    if (account.len > SIZE_MAX - (sizeof(prefix) - 1 + sizeof(suffix) - 1))
        rc = snow_fail(error, "Snowflake URL size overflow");
    size_t url_len = sizeof(prefix) - 1 + account.len + sizeof(suffix) - 1;
    if (rc == 0) {
        url = malloc(url_len + 1);
        if (!url) rc = snow_fail(error, "cannot allocate Snowflake URL");
        else {
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, account.data, account.len);
            memcpy(url + sizeof(prefix) - 1 + account.len, suffix, sizeof(suffix));
        }
    }
    const char *cause = NULL;
    char owned[160];
    if (rc == 0 && !ctx) cause = "failed to create request: net/http: nil Context";
    else if (rc == 0 && memchr(url, '\0', url_len))
        cause = "failed to create request: net/url: invalid control character in URL";
    if (rc == 0 && !cause && ctx) {
        br_go_url_parts parts = {0};
        br_go_url_error rejection = {0};
        char *fatal = NULL;
        int parsed = br_go_url_parse((br_slice){(const unsigned char *)url, url_len}, &parts,
                                     &rejection, &fatal);
        if (parsed < 0) rc = snow_fail(error, fatal ? fatal : "cannot parse Snowflake URL");
        else if (rejection.kind != BR_GO_URL_OK)
            cause = "failed to create request: net/url: invalid control character in URL";
        br_go_url_clear(&parts);
        free(fatal);
    }
    if (rc == 0 && !cause) {
        const br_header headers[] = {
            {"Content-Type", "application/json"},
            {"Accept", "application/json"},
            {"X-Snowflake-Authorization-Token-Type", "BASIC"},
        };
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 3,
            .body = {(const unsigned char *)body, body_len},
            .timeout_ms = 3000, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            if (send_error) {
                snprintf(owned, sizeof(owned), "failed to send request: %s", send_error);
                cause = owned;
            }
        } else if (response.body_error) {
            snprintf(owned, sizeof(owned), "failed to read response body: %s", response.body_error);
            cause = owned;
        } else if (response.status == 200) {
            bool success = false;
            char *parse = NULL;
            int decoded = snow_success(response.body, &success, &parse);
            if (decoded < 0) rc = snow_fail(error, "cannot parse Snowflake response");
            else if (decoded > 0) {
                if (parse) {
                    snprintf(owned, sizeof(owned), "failed to parse response: %s", parse);
                    cause = owned;
                }
            } else result->verified = success;
            free(parse);
        }
        br_http_release(ctx, &response);
        free(send_error);
    }
    if (rc == 0) rc = snow_cause(result, cause, password, error);
    free(url);
    free(body);
    return rc;
}

static int snow_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !patterns[2] || !out ||
        (!input.data && input.len))
        return snow_fail(error, "invalid or uninitialized Snowflake scan");
    for (size_t at = 0; at < input.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){input.data + at, input.len - at}, &rune);
        if (!width) return snow_fail(error, "unsupported: Snowflake invalid UTF-8");
        at += width;
    }
    size_t original_len = out->len;
    br_captures accounts = {0}, usernames = {0}, passwords = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &accounts, true, &owned_error);
    if (rc == 0 && accounts.len)
        rc = br_captures_find(patterns[1], input, &usernames, false, &owned_error);
    if (rc == 0 && accounts.len && usernames.len)
        rc = br_captures_find(patterns[2], input, &passwords, false, &owned_error);
    for (size_t a = 0; rc == 0 && a < accounts.len; ++a) {
        br_slice account;
        rc = snow_trim(br_captures_at(&accounts, a), &account, &owned_error);
        for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
            br_slice username;
            rc = snow_trim(br_captures_at(&usernames, u), &username, &owned_error);
            for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
                br_slice password;
                bool ok = false;
                if (rc == 0) rc = snow_trim(br_captures_at(&passwords, p), &password, &owned_error);
                if (rc == 0) rc = snow_password_ok(password, &ok, &owned_error);
                if (rc != 0 || !ok) continue;
                br_result result = {0};
                if (br_finding_key_bytes(&result, detector->type, password, "key") != 0 ||
                    snow_extra(&result, account, username, &owned_error) != 0)
                    rc = snow_fail(&owned_error, "cannot create Snowflake result");
                else if (verify)
                    rc = snow_verify(ctx, account, username, password, &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = snow_fail(&owned_error, "cannot append Snowflake result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&accounts);
    br_captures_clear(&usernames);
    br_captures_clear(&passwords);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const snow_keywords[] = {"snowflake"};
static const char *const snow_account_prefix[] = {"account"};
static br_regex *snow_patterns[3];
static br_detector snow_detector = {
    .type = 927, .version = 0, .name = "Snowflake", .custom_name = "",
    .description = "Snowflake is a cloud data platform that provides data warehousing, data lakes, data sharing, and data exchange capabilities. Snowflake credentials can be used to access and manipulate data stored in Snowflake.",
    .keywords = snow_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = snow_scan,
};

int br_snowflake_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return snow_fail(error, "invalid Snowflake detector output");
    *out = NULL;
    if (!snow_patterns[0] &&
        br_regex_compile_prefixed(snow_account_prefix, 1,
                                  "\\b([a-zA-Z]{7}-[0-9a-zA-Z-_]{1,255}(.privatelink)?)\\b",
                                  &snow_patterns[0], error) != 0)
        return -1;
    /* Go stdlib (?im) username/password checks. \\s is HT/LF/FF/CR/space.
     * %+v inserts the exclusion; \\+ is a literal plus, not a backslash. */
    if (!snow_patterns[1] &&
        br_regex_compile(
            "(?:[uU][sS\\x{017F}][eE][rR]|[uU][sS\\x{017F}][rR])"
            "[^\\x09\\x0a\\x0c\\x0d ]{0,40}?[:=\\x09\\x0a\\x0c\\x0d ]{1,3}[ '\"=]{0,1}"
            "([^:!@#$%^&*{}:<>,.;?()/+=\\x09\\x0a\\x0c\\x0d ]{4,40})\\b",
            &snow_patterns[1], error) != 0)
        return -1;
    if (!snow_patterns[2] &&
        br_regex_compile(
            "(?:[pP][aA][sS\\x{017F}][sS\\x{017F}]|[pP][aA][sS\\x{017F}][sS\\x{017F}][wW][oO][rR][dD])"
            "[^\\x09\\x0a\\x0c\\x0d ]{0,40}?[:=\\x09\\x0a\\x0c\\x0d ]{1,3}[ '\"=]{0,1}"
            "([^:\\x0d\\x0a ]{4,40})",
            &snow_patterns[2], error) != 0)
        return -1;
    snow_detector.state = snow_patterns;
    *out = &snow_detector;
    return 0;
}
