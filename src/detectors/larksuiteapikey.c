/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/larksuiteapikey/larksuiteapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *id;
    br_regex *secret;
} larksuite_patterns;

typedef struct {
    intptr_t code;
    br_json *msg;
    char *cause;
} larksuite_fields;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Always call, including a nil cause. Redact the app id only. */
static int set_cause(br_result *result, br_slice id, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, &id, 1) != 0)
        return fail(error, "cannot record LarkSuiteApiKey verification error");
    return 0;
}

static br_slice number_text(br_slice encoded)
{
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    return encoded;
}

static bool parse_code(br_slice number, intptr_t *out)
{
    size_t at = 0;
    bool negative = number.len && number.data[0] == '-';
    if (negative) ++at;
    if (at == number.len) return false;
    uintptr_t limit = (uintptr_t)INTPTR_MAX + (negative ? 1u : 0u), magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false;
        uintptr_t digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    if (!negative) *out = (intptr_t)magnitude;
    else if (magnitude == (uintptr_t)INTPTR_MAX + 1u) *out = INTPTR_MIN;
    else *out = -(intptr_t)magnitude;
    return true;
}

static int number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field verificationResponse.code of type int";
    size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - fixed) return -1;
    *cause = malloc(fixed + number.len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

static int read_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    larksuite_fields *fields = user;
    /* Primitive null never resets an earlier assignment. A sole null stays zero. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (br_json_field_name(name, "code")) {
        if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
            br_slice number = number_text(encoded);
            intptr_t code;
            if (parse_code(number, &code)) fields->code = code;
            else if (!fields->cause && number_cause(number, &fields->cause) != 0) return -1;
        } else if (!fields->cause &&
                   br_json_type_cause(value, "verificationResponse.code", "int", &fields->cause) != 0)
            return -1;
    } else if (br_json_field_name(name, "msg")) {
        if (json_object_is_type(value, json_type_string)) {
            json_object_put(fields->msg);
            fields->msg = json_object_get(value);
        } else if (!fields->cause &&
                   br_json_type_cause(value, "verificationResponse.msg", "string", &fields->cause) != 0)
            return -1;
    }
    /* First type error stays. Later members still run so an allocation failure
     * is not hidden behind that ordinary cause. */
    return 0;
}

static int format_failure(intptr_t code, br_slice msg, char **cause)
{
    char number[32];
    int n = snprintf(number, sizeof(number), "%" PRIdPTR, code);
    if (n < 0 || (size_t)n >= sizeof(number)) return -1;
    static const char prefix[] = "verification failed code ";
    static const char middle[] = ", message ";
    size_t fixed = sizeof(prefix) - 1 + sizeof(middle) - 1;
    if (msg.len > SIZE_MAX - fixed - (size_t)n - 1) return -1;
    char *text = malloc(fixed + (size_t)n + msg.len + 1);
    if (!text) return -1;
    size_t at = 0;
    memcpy(text + at, prefix, sizeof(prefix) - 1);
    at += sizeof(prefix) - 1;
    memcpy(text + at, number, (size_t)n);
    at += (size_t)n;
    memcpy(text + at, middle, sizeof(middle) - 1);
    at += sizeof(middle) - 1;
    if (msg.len) memcpy(text + at, msg.data, msg.len);
    text[at + msg.len] = '\0';
    *cause = text;
    return 0;
}

static int fatal_decode(br_json *root, larksuite_fields *fields, const char **fatal, const char *message)
{
    json_object_put(root);
    json_object_put(fields->msg);
    free(fields->cause);
    fields->cause = NULL;
    if (fatal) *fatal = message;
    return -1;
}

/* 0 is a decoded document, 1 owns an ordinary cause, -1 is fatal.
 * Document status 1 stays ordinary. Every visitor nonzero, including +1, is fatal. */
static int decode_body(br_slice body, const char *read_error, bool *verified, char **cause,
                       const char **fatal)
{
    larksuite_fields fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    if (fatal) *fatal = NULL;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (rc < 0) return fatal_decode(root, &fields, fatal, "cannot decode LarkSuite verification response");
    if (rc == 0 && root && !json_object_is_type(root, json_type_null)) {
        if (json_object_is_type(root, json_type_object)) {
            int visit = br_json_each_member((br_slice){body.data, end}, read_member, &fields);
            if (visit != 0)
                return fatal_decode(root, &fields, fatal, "cannot decode LarkSuite verification response");
        } else if (br_json_type_cause(root, NULL, "larksuiteapikey.verificationResponse", &fields.cause) != 0)
            return fatal_decode(root, &fields, fatal, "cannot decode LarkSuite verification response");
        else rc = 1;
    }
    json_object_put(root);
    if (rc == 0 && fields.cause) rc = 1;
    if (rc == 0 && fields.code != 0) {
        br_slice msg = br_json_text(fields.msg);
        /* Guard only a message that would be published. Do not truncate it. */
        if (msg.len && memchr(msg.data, '\0', msg.len))
            return fatal_decode(NULL, &fields, fatal,
                                "unsupported: LarkSuiteApiKey verification message contains embedded NUL");
        if (format_failure(fields.code, msg, &fields.cause) != 0)
            return fatal_decode(NULL, &fields, fatal, "cannot decode LarkSuite verification response");
        rc = 1;
    }
    json_object_put(fields.msg);
    *verified = rc == 0;
    *cause = fields.cause;
    return rc;
}

static int verify_larksuite(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                            br_result *result, char **error)
{
    static const char head[] = "{\"app_id\": \"";
    static const char mid[] = "\", \"app_secret\": \"";
    static const char tail[] = "\"}";
    size_t body_len = sizeof(head) - 1 + id.len + sizeof(mid) - 1 + secret.len + sizeof(tail) - 1;
    char *body = malloc(body_len + 1);
    if (!body) return fail(error, "out of memory constructing LarkSuite request body");
    size_t at = 0;
    memcpy(body + at, head, sizeof(head) - 1);
    at += sizeof(head) - 1;
    memcpy(body + at, id.data, id.len);
    at += id.len;
    memcpy(body + at, mid, sizeof(mid) - 1);
    at += sizeof(mid) - 1;
    memcpy(body + at, secret.data, secret.len);
    at += secret.len;
    memcpy(body + at, tail, sizeof(tail));
    /* The literal body exists before the constructor. A nil context is not a drop. */
    if (!ctx) {
        free(body);
        return set_cause(result, id, "net/http: nil Context", error);
    }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST",
        .url = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal",
        .headers = headers,
        .nheaders = 1,
        .body = {(const unsigned char *)body, body_len},
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int status = response.status;
    br_slice response_body = response.body;
    const char *read_error = response.body_error;
    char *decoded = NULL;
    bool verified = false;
    int decoded_rc = 0;
    const char *fatal = NULL;
    /* Only 200 is decoded, and the response bytes must be read before release. */
    if (sent == 0 && status == 200)
        decoded_rc = decode_body(response_body, read_error, &verified, &decoded, &fatal);
    br_http_release(ctx, &response);
    free(body);
    if (decoded_rc < 0) {
        free(decoded);
        free(send_error);
        return fail(error, fatal ? fatal : "cannot decode LarkSuite verification response");
    }
    const char *cause = NULL;
    if (sent != 0) cause = send_error;
    else if (status == 200) {
        result->verified = verified;
        cause = decoded;
    }
    int rc = set_cause(result, id, cause, error);
    free(decoded);
    free(send_error);
    return rc;
}

static int scan_larksuite(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized LarkSuiteApiKey scan");
    const larksuite_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->secret)
        return fail(error, "invalid or uninitialized LarkSuiteApiKey scan");
    size_t original_len = out->len;
    br_captures ids = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            br_slice id = br_captures_at(&ids, i);
            br_slice secret = br_captures_at(&secrets, s);
            /* Raw is the id. RawV2 is id concatenated with secret. A nearby id
             * does not remove the secret from the product. */
            if (br_finding_pair_bytes(&result, detector->type, id, "key", secret, "secret", (br_slice){0}) != 0) {
                fail(&owned_error, "cannot create LarkSuiteApiKey finding");
                rc = -1;
            } else if (verify && verify_larksuite(ctx, id, secret, &result, &owned_error) != 0) {
                rc = -1;
            } else if (br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append LarkSuiteApiKey finding");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const prefixes[] = {"lark", "larksuite"};
static const char *const keywords[] = {"lark", "larksuite", "cli_"};
static larksuite_patterns compiled;
static br_detector larksuite = {
    .type = 992,
    .version = 0,
    .name = "LarkSuiteApiKey",
    .custom_name = "",
    .description = "LarkSuite is a collaboration platform that provides tools for communication, calendar, and cloud storage. LarkSuite API keys can be used to access and manage these services programmatically.",
    .keywords = keywords,
    .nkeywords = 3,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = 1024,
    .state = &compiled,
    .scan = scan_larksuite,
};

int br_larksuiteapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid LarkSuiteApiKey detector output");
    *out = NULL;
    if (!compiled.id &&
        br_regex_compile_prefixed(prefixes, 2, "\\b(cli_[a-z0-9A-Z]{16})\\b", &compiled.id, error) != 0)
        return -1;
    if (!compiled.secret &&
        br_regex_compile_prefixed(prefixes, 2, "\\b([a-z0-9A-Z]{32})\\b", &compiled.secret, error) != 0)
        return -1;
    *out = &larksuite;
    return 0;
}
