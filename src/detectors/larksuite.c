/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/larksuite/larksuite.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int larksuite_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef enum { LARK_TENANT = 0, LARK_USER = 1, LARK_APP = 2 } lark_kind;

static const char *const token_types[] = {
    "Tenant Access Token", "User Access Token", "App Access Token",
};
static const char *const urls[] = {
    "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
    "https://open.larksuite.com/open-apis/authen/v1/user_info",
    "https://open.larksuite.com/open-apis/calendar/v4/calendars",
};
static const char *const suffixes[] = {
    "(?:^|[^-])\\b(t-[a-z0-9A-Z_.]{14,50})\\b(?:[^-]|$)",
    "(?:^|[^-])\\b(u-[a-z0-9A-Z_.]{14,50})\\b(?:[^-]|$)",
    "(?:^|[^-])\\b(a-[a-z0-9A-Z_.]{14,50})\\b(?:[^-]|$)",
};
static const char *const tenant_prefixes[] = {"lark", "larksuite", "tenant"};
static const char *const user_prefixes[] = {"lark", "larksuite", "user"};
static const char *const app_prefixes[] = {"lark", "larksuite", "app"};
static const char *const *const prefix_sets[] = {tenant_prefixes, user_prefixes, app_prefixes};

typedef struct { br_regex *patterns[3]; } lark_patterns;
static lark_patterns lark_state;

static int set_cause(br_result *result, const char *cause, br_slice token, char **error)
{
    /* Source always passes the token, including a nil cause. +1 is fatal. */
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return larksuite_fail(error, "cannot store LarkSuite verification error");
    return 0;
}

static bool space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* Go unmarshals an integer field from the original literal, not a float. */
static bool parse_int(br_slice encoded, int64_t *out)
{
    size_t i = 0;
    while (i < encoded.len && space(encoded.data[i])) ++i;
    if (i == encoded.len) return false;
    int sign = 1;
    if (encoded.data[i] == '-') {
        sign = -1;
        ++i;
    }
    if (i == encoded.len || encoded.data[i] < '0' || encoded.data[i] > '9') return false;
    uint64_t mag = 0;
    for (; i < encoded.len && encoded.data[i] >= '0' && encoded.data[i] <= '9'; ++i) {
        unsigned digit = (unsigned)(encoded.data[i] - '0');
        if (mag > (uint64_t)INT64_MAX / 10 ||
            (mag == (uint64_t)INT64_MAX / 10 && digit > (sign < 0 ? 8u : 7u)))
            return false;
        mag = mag * 10 + digit;
    }
    while (i < encoded.len && space(encoded.data[i])) ++i;
    if (i != encoded.len) return false;
    if (sign < 0)
        *out = mag == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)mag;
    else
        *out = (int64_t)mag;
    return true;
}

typedef struct {
    int64_t code;
    char *msg;
    size_t msg_len;
    bool bad;
    char *cause;
} decoded;

static void decoded_clear(decoded *fields)
{
    free(fields->msg);
    free(fields->cause);
    *fields = (decoded){0};
}

static int note_type(decoded *fields, br_json *value, const char *field, const char *expected)
{
    if (fields->bad) return 0;
    fields->bad = true;
    return br_json_type_cause(value, field, expected, &fields->cause) == 0 ? 0 : -1;
}

/* A failed integer keeps the original lexeme, including an exponent or range error. */
static br_slice number_lexeme(br_slice encoded)
{
    while (encoded.len && space(encoded.data[0])) {
        ++encoded.data;
        --encoded.len;
    }
    while (encoded.len && space(encoded.data[encoded.len - 1])) --encoded.len;
    return encoded;
}

static int note_number(decoded *fields, br_slice encoded)
{
    if (fields->bad) return 0;
    br_slice number = number_lexeme(encoded);
    if (!number.data || !number.len) return -1;
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field verificationResponse.code of type int";
    size_t fixed = sizeof(prefix) - 1 + sizeof(suffix) - 1;
    if (number.len > SIZE_MAX - fixed - 1) return -1;
    char *cause = malloc(fixed + number.len + 1);
    if (!cause) return -1;
    memcpy(cause, prefix, sizeof(prefix) - 1);
    memcpy(cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    fields->bad = true;
    fields->cause = cause;
    return 0;
}

static int copy_msg(decoded *fields, br_slice text)
{
    if (text.len > INT_MAX || (!text.data && text.len)) return -1;
    char *next = malloc(text.len + 1);
    if (!next) return -1;
    if (text.len) memcpy(next, text.data, text.len);
    next[text.len] = '\0';
    free(fields->msg);
    fields->msg = next;
    fields->msg_len = text.len;
    return 0;
}

static int read_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    decoded *fields = user;
    if (br_json_field_name(name, "code")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
            int64_t code = 0;
            if (!parse_int(encoded, &code)) return note_number(fields, encoded);
            fields->code = code; /* Later valid values still land after a sticky cause. */
            return 0;
        }
        return note_type(fields, value, "verificationResponse.code", "int");
    }
    if (br_json_field_name(name, "msg")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return note_type(fields, value, "verificationResponse.msg", "string");
        /* A sticky type error still owns the message copy. */
        return copy_msg(fields, br_json_text(value));
    }
    return 0;
}

/* 0 success, 1 ordinary document/type cause, -1 resource or visitor failure.
 * Missing and null code stay 0. Document status 1 is not a visitor status. */
static int decode_response(const br_http_response *response, decoded *fields, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &fields->cause);
    if (rc < 0) {
        json_object_put(root);
        return larksuite_fail(error, "cannot decode LarkSuite response");
    }
    if (rc == 1) {
        json_object_put(root);
        if (!fields->cause) return larksuite_fail(error, "cannot decode LarkSuite response");
        return 1;
    }
    /* First-document success stands, including a terminal body_error. */
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            if (br_json_type_cause(root, NULL, "larksuite.verificationResponse", &fields->cause) != 0)
                rc = -1;
            else fields->bad = true;
        } else if (response->body.data && end)
            rc = br_json_each_member((br_slice){response->body.data, end}, read_member, fields);
    }
    json_object_put(root);
    if (rc != 0) {
        /* Every visitor nonzero, including +1 after a sticky type error, is fatal. */
        return larksuite_fail(error, rc > 0 ? "cannot visit LarkSuite response"
                                            : "cannot decode LarkSuite response");
    }
    if (fields->bad) {
        if (!fields->cause) return larksuite_fail(error, "cannot decode LarkSuite response");
        return 1;
    }
    return 0;
}

static bool invalid_code(int64_t code)
{
    switch (code) {
    case 20005: case 20008: case 20021: case 20022: case 20023:
    case 99991663: case 99991668:
        return true;
    default:
        return false;
    }
}

static bool contains_nul(const char *text, size_t len)
{
    return text && len && memchr(text, '\0', len) != NULL;
}

static int format_decode(int status, const char *cause, char **out, char **error)
{
    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix), "failed to decode response (status %d): ", status);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix) || !cause)
        return larksuite_fail(error, "cannot store LarkSuite verification error");
    size_t cause_len = strlen(cause);
    char *text = malloc((size_t)prefix_len + cause_len + 1);
    if (!text) return larksuite_fail(error, "cannot store LarkSuite verification error");
    memcpy(text, prefix, (size_t)prefix_len);
    memcpy(text + prefix_len, cause, cause_len + 1);
    *out = text;
    return 0;
}

/* Format only a reached unknown-code message. Valid, invalid and decode paths ignore it. */
static int format_failed(int status, const decoded *fields, char **out, char **error)
{
    if (contains_nul(fields->msg, fields->msg_len))
        return larksuite_fail(error, "unsupported: LarkSuite verification message");
    char prefix[96];
    int prefix_len = snprintf(prefix, sizeof(prefix),
                              "verification failed (status %d, code %" PRId64 "): ",
                              status, fields->code);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix))
        return larksuite_fail(error, "cannot store LarkSuite verification error");
    char *text = malloc((size_t)prefix_len + fields->msg_len + 1);
    if (!text) return larksuite_fail(error, "cannot store LarkSuite verification error");
    memcpy(text, prefix, (size_t)prefix_len);
    if (fields->msg_len) memcpy(text + prefix_len, fields->msg, fields->msg_len);
    text[prefix_len + fields->msg_len] = '\0';
    *out = text;
    return 0;
}

static int prepare_decision(int status, const decoded *fields, bool *verified, char **owned, char **error)
{
    *verified = false;
    *owned = NULL;
    if (fields->code == 0 || fields->code == 99991672) {
        *verified = true;
        return 0;
    }
    if (invalid_code(fields->code)) return 0;
    return format_failed(status, fields, owned, error);
}

static int larksuite_verify(const br_scan_ctx *ctx, lark_kind kind, br_slice token,
                            br_result *result, char **error)
{
    if (!ctx) return set_cause(result, "net/http: nil Context", token, error);
    if (token.len < 16 || token.len > 52 || !token.data)
        return larksuite_fail(error, "invalid LarkSuite token");
    char authorization[60];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = urls[kind],
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int rc = 0;
    bool do_setter = false;
    bool want_verified = false;
    const char *setter_cause = NULL;
    char *owned = NULL;
    decoded fields = {0};
    bool decoded = false;
    if (send_rc != 0) {
        do_setter = true;
        setter_cause = transport_error;
    } else {
        int decoded_rc = decode_response(&response, &fields, error);
        decoded = true;
        if (decoded_rc < 0) rc = -1;
        else if (decoded_rc > 0) {
            if (format_decode(response.status, fields.cause, &owned, error) != 0) rc = -1;
            else {
                do_setter = true;
                setter_cause = owned;
            }
        } else if (prepare_decision(response.status, &fields, &want_verified, &owned, error) != 0)
            rc = -1;
        else {
            do_setter = true;
            setter_cause = owned;
        }
    }
    /* One release for an attempted send, including fatal cleanup. The verdict
     * and mandatory setter happen only after that release. */
    br_http_release(ctx, &response);
    if (decoded) decoded_clear(&fields);
    if (rc == 0 && do_setter) {
        if (want_verified) result->verified = true;
        if (set_cause(result, setter_cause, token, error) != 0) rc = -1;
    }
    free(owned);
    free(transport_error);
    return rc;
}

static int add_extra(br_result *result, lark_kind kind, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *value = json_object_new_string(token_types[kind]);
    if (!result->extra_data || !value) {
        json_object_put(value);
        return larksuite_fail(error, "cannot create LarkSuite extra data");
    }
    if (json_object_object_add(result->extra_data, "token_type", value) != 0) {
        json_object_put(value);
        return larksuite_fail(error, "cannot create LarkSuite extra data");
    }
    return 0;
}

static int larksuite_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const lark_patterns *state = detector ? detector->state : NULL;
    if (!state || !state->patterns[0] || !out || (!input.data && input.len))
        return larksuite_fail(error, "invalid or uninitialized LarkSuite scan");
    size_t original_len = out->len;
    char *owned_error = NULL;
    int rc = 0;
    /* Tenant, then user, then app. Unique and first-seen within each type.
     * The span hint is not a match filter. */
    for (lark_kind kind = LARK_TENANT; rc == 0 && kind <= LARK_APP; ++kind) {
        br_captures keys = {0};
        rc = br_captures_find(state->patterns[kind], input, &keys, true, &owned_error);
        for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
            br_result result = {0};
            br_slice token = br_captures_at(&keys, i);
            if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                rc = larksuite_fail(&owned_error, "cannot create LarkSuite result");
            else if (add_extra(&result, kind, &owned_error) != 0)
                rc = -1;
            else if (verify && larksuite_verify(ctx, kind, token, &result, &owned_error) != 0)
                rc = -1;
            else if (br_results_push(out, &result) != 0)
                rc = larksuite_fail(&owned_error, "cannot append LarkSuite result");
            br_result_clear(&result);
        }
        br_captures_clear(&keys);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

/* path.Ext: slash is the only separator. The suffix starts at the last dot. */
static br_slice path_ext(br_slice raw)
{
    if (!raw.data || !raw.len) return (br_slice){0};
    for (size_t i = raw.len; i > 0; --i) {
        unsigned char c = raw.data[i - 1];
        if (c == '/') return (br_slice){0};
        if (c == '.') return (br_slice){raw.data + i - 1, raw.len - (i - 1)};
    }
    return (br_slice){0};
}

static bool listed_extension(br_slice ext)
{
    static const char *const extensions[] = {
        ".html", ".htm", ".css", ".js", ".json", ".xml", ".svg", ".php", ".asp", ".aspx", ".jsp",
        ".txt", ".md", ".pdf", ".doc", ".docx", ".rtf", ".csv", ".xlsx", ".xls", ".sql", ".db",
        ".conf", ".config", ".ini", ".yaml", ".yml", ".toml", ".log", ".out", ".err",
        ".zip", ".tar", ".gz", ".rar", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
        ".go", ".py", ".java", ".cpp", ".c", ".h", ".rb", ".rs", ".ts", ".tmp", ".bak", ".old", ".lock",
    };
    if (!ext.data || !ext.len || ext.len >= 16) return false;
    char lower[16];
    for (size_t i = 0; i < ext.len; ++i) {
        unsigned char c = ext.data[i];
        lower[i] = (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    lower[ext.len] = '\0';
    for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); ++i)
        if (!strcmp(lower, extensions[i])) return true;
    return false;
}

static bool larksuite_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    if (!result) {
        if (reason) *reason = NULL;
        return false;
    }
    if (listed_extension(path_ext((br_slice){result->raw.data, result->raw.len}))) {
        /* Always true. Allocate an empty reason only when the output is requested. */
        if (reason) *reason = strdup("");
        return true;
    }
    static const char *const terms[] = {
        "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****",
    };
    return br_known_false_positive((br_slice){result->raw.data, result->raw.len}, terms, 7, true, reason);
}

static const char *const larksuite_keywords[] = {"lark", "larksuite"};
static br_detector larksuite_detector = {
    .type = 991,
    .version = 0,
    .name = "LarkSuite",
    .custom_name = "",
    .description = "LarkSuite is a collaborative suite that includes chat, calendar, and cloud storage features. The detected token can be used to access and interact with these services.",
    .keywords = larksuite_keywords,
    .nkeywords = 2,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = 1024,
    .state = &lark_state,
    .scan = larksuite_scan,
    .false_positive = larksuite_false_positive,
};

int br_larksuite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return larksuite_fail(error, "invalid LarkSuite detector output");
    *out = NULL;
    if (!lark_state.patterns[0] || !lark_state.patterns[1] || !lark_state.patterns[2]) {
        for (size_t i = 0; i < 3; ++i) {
            if (lark_state.patterns[i]) continue;
            if (br_regex_compile_prefixed(prefix_sets[i], 3, suffixes[i], &lark_state.patterns[i], error) != 0) {
                for (size_t j = 0; j < 3; ++j) {
                    br_regex_free(lark_state.patterns[j]);
                    lark_state.patterns[j] = NULL;
                }
                return -1;
            }
        }
    }
    *out = &larksuite_detector;
    return 0;
}
