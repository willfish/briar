/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aws/session_keys/sessionkey.go
 * and aws/common.go. This is the manual GET/JSON verifier, not the AWS SDK. */
#include "detectors.h"
#include "aws_common.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char request_url[] = "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";
static const char deny_reason[] = "Account ID is in the deny list for verification";
static const char allow_reason[] = "Account ID is not in the allow list for verification";
typedef struct { br_regex *id, *secret, *session; } session_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int textf(char **out, const char *format, ...)
{
    va_list args, copy;
    va_start(args, format);
    va_copy(copy, args);
    int len = vsnprintf(NULL, 0, format, args);
    va_end(args);
    *out = len < 0 ? NULL : malloc((size_t)len + 1);
    if (*out) vsnprintf(*out, (size_t)len + 1, format, copy);
    va_end(copy);
    return *out ? 0 : -1;
}

static int put_text(br_json *object, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (!json_object_object_add(object, name, value)) return 0;
    json_object_put(value);
    return -1;
}

static int put_literal(br_json *object, const char *name, const char *text)
{
    return put_text(object, name, (br_slice){(const unsigned char *)text, strlen(text)});
}

static int sha256_hex(const void *data, size_t len, char out[65])
{
    unsigned char hash[32];
    size_t count = 0;
    if (!EVP_Q_digest(NULL, "SHA256", NULL, data, len, hash, &count) || count != 32) return -1;
    for (size_t i = 0; i < 32; ++i) snprintf(out + 2 * i, 3, "%02x", hash[i]);
    return 0;
}

static int hmac256(const void *key, size_t len, const char *text, unsigned char out[32])
{
    size_t count = 0;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, len,
                     (const unsigned char *)text, strlen(text), out, 32, &count) && count == 32 ? 0 : -1;
}

/* 0 signed, 1 clock/crypto cause, -1 allocation failure. The security-token
 * header borrows the complete NUL-terminated capture, with no fixed-size copy. */
static int sign_request(const char *id, const char *secret, const char *session,
                         char date[17], char auth[512], char **cause)
{
    struct timespec now;
    struct tm utc;
    if (clock_gettime(CLOCK_REALTIME, &now) || !gmtime_r(&now.tv_sec, &utc) ||
        strftime(date, 17, "%Y%m%dT%H%M%SZ", &utc) != 16) goto unsupported;
    char day[9]; memcpy(day, date, 8); day[8] = '\0';
    static const char signed_headers[] = "host;x-amz-date;x-amz-security-token";
    char payload[65], canonical_hash[65], scope[80], to_sign[256];
    if (sha256_hex("", 0, payload)) goto unsupported;
    char prefix[256];
    int n = snprintf(prefix, sizeof(prefix),
        "GET\n/\nAction=GetCallerIdentity&Version=2011-06-15\nhost:sts.amazonaws.com\n"
        "x-amz-date:%s\nx-amz-security-token:", date);
    if (n < 0 || (size_t)n >= sizeof(prefix)) goto unsupported;
    static const char tail[] = "\n\nhost;x-amz-date;x-amz-security-token\n";
    size_t len = strlen(session), overhead = (size_t)n + sizeof(tail) - 1 + 64 + 1;
    if (len > SIZE_MAX - overhead) return -1;
    char *canonical = malloc(len + overhead);
    if (!canonical) return -1;
    memcpy(canonical, prefix, (size_t)n);
    memcpy(canonical + n, session, len);
    memcpy(canonical + n + len, tail, sizeof(tail) - 1);
    memcpy(canonical + n + len + sizeof(tail) - 1, payload, 65);
    int hashed = sha256_hex(canonical, len + overhead - 1, canonical_hash);
    free(canonical);
    if (hashed) goto unsupported;
    snprintf(scope, sizeof(scope), "%s/us-east-1/sts/aws4_request", day);
    snprintf(to_sign, sizeof(to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", date, scope, canonical_hash);
    char key[45]; snprintf(key, sizeof(key), "AWS4%s", secret);
    unsigned char k_date[32], k_region[32], k_service[32], k_signing[32], signature[32];
    if (hmac256(key, strlen(key), day, k_date) || hmac256(k_date, 32, "us-east-1", k_region) ||
        hmac256(k_region, 32, "sts", k_service) || hmac256(k_service, 32, "aws4_request", k_signing) ||
        hmac256(k_signing, 32, to_sign, signature)) goto unsupported;
    char hex[65];
    for (size_t i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", signature[i]);
    n = snprintf(auth, 512, "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
                 id, scope, signed_headers, hex);
    if (n > 0 && n < 512) return 0;
unsupported:
    *cause = strdup("unsupported: AWS session signing clock or crypto failure");
    return *cause ? 1 : -1;
}

typedef struct {
    br_json *account, *arn, *user_id, *code, *message;
    char *cause;
} session_json;

static int type_cause(session_json *fields, br_json *value, const char *field, const char *expected)
{
    return br_json_type_cause(value, field, expected, &fields->cause) ? -1 : 1;
}

/* Null does not reset an existing non-pointer Go string or struct. */
static int read_string(session_json *fields, br_json *value, br_json **out, const char *field)
{
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_string)) return type_cause(fields, value, field, "string");
    if (out) { json_object_put(*out); *out = json_object_get(value); }
    return 0;
}

static int read_result(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    session_json *fields = user;
    if (br_json_field_name(name, "account"))
        return read_string(fields, value, &fields->account, ".GetCallerIdentityResponse.GetCallerIdentityResult.Account");
    if (br_json_field_name(name, "arn"))
        return read_string(fields, value, &fields->arn, ".GetCallerIdentityResponse.GetCallerIdentityResult.Arn");
    if (br_json_field_name(name, "userid"))
        return read_string(fields, value, &fields->user_id, ".GetCallerIdentityResponse.GetCallerIdentityResult.UserId");
    return 0;
}

static int read_metadata(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    return br_json_field_name(name, "requestid") ?
        read_string(user, value, NULL, ".GetCallerIdentityResponse.ResponseMetadata.RequestId") : 0;
}

static int read_identity_response(void *user, br_slice name, br_json *value, br_slice encoded)
{
    session_json *fields = user;
    if (!value) return 0;
    if (br_json_field_name(name, "getcalleridentityresult")) {
        if (!json_object_is_type(value, json_type_object))
            return type_cause(fields, value, ".GetCallerIdentityResponse.GetCallerIdentityResult",
                "struct { Account string \"json:\\\"Account\\\"\"; Arn string \"json:\\\"Arn\\\"\"; UserID string \"json:\\\"UserId\\\"\" }");
        return br_json_each_member(encoded, read_result, fields);
    }
    if (br_json_field_name(name, "responsemetadata")) {
        if (!json_object_is_type(value, json_type_object))
            return type_cause(fields, value, ".GetCallerIdentityResponse.ResponseMetadata",
                "struct { RequestID string \"json:\\\"RequestId\\\"\" }");
        return br_json_each_member(encoded, read_metadata, fields);
    }
    return 0;
}

static int read_identity_root(void *user, br_slice name, br_json *value, br_slice encoded)
{
    session_json *fields = user;
    if (!value || !br_json_field_name(name, "getcalleridentityresponse")) return 0;
    if (!json_object_is_type(value, json_type_object))
        return type_cause(fields, value, "IdentityResponse.GetCallerIdentityResponse",
            "struct { GetCallerIdentityResult struct { Account string \"json:\\\"Account\\\"\"; Arn string \"json:\\\"Arn\\\"\"; UserID string \"json:\\\"UserId\\\"\" } \"json:\\\"GetCallerIdentityResult\\\"\"; ResponseMetadata struct { RequestID string \"json:\\\"RequestId\\\"\" } \"json:\\\"ResponseMetadata\\\"\" }");
    return br_json_each_member(encoded, read_identity_response, fields);
}

static int read_error(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    session_json *fields = user;
    if (br_json_field_name(name, "code")) return read_string(fields, value, &fields->code, "Error.Error.Code");
    if (br_json_field_name(name, "message")) return read_string(fields, value, &fields->message, "Error.Error.Message");
    return 0;
}

static int read_error_root(void *user, br_slice name, br_json *value, br_slice encoded)
{
    session_json *fields = user;
    if (!value || !br_json_field_name(name, "error")) return 0;
    if (!json_object_is_type(value, json_type_object))
        return type_cause(fields, value, "ErrorResponseBody.Error", "aws.Error");
    return br_json_each_member(encoded, read_error, fields);
}

static int decode_response(const br_http_response *response, bool identity, session_json *fields)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &fields->cause);
    if (!rc && root) {
        if (!json_object_is_type(root, json_type_object))
            rc = type_cause(fields, root, NULL, identity ? "aws.IdentityResponse" : "aws.ErrorResponseBody");
        else rc = br_json_each_member((br_slice){response->body.data, end},
                                      identity ? read_identity_root : read_error_root, fields);
    }
    json_object_put(root);
    return rc;
}

/* Go EqualFold against these ASCII literals also accepts long-s/Kelvin sign.
 * Check full byte lengths, so an embedded NUL is not a matching error code. */
static bool equal_code(br_slice text, const char *lower)
{
    size_t at = 0;
    for (size_t i = 0; lower[i]; ++i) {
        if (at == text.len) return false;
        unsigned char c = text.data[at++];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c == (unsigned char)lower[i]) continue;
        if (lower[i] == 's' && c == 0xc5 && at < text.len && text.data[at] == 0xbf) { ++at; continue; }
        if (lower[i] == 'k' && c == 0xe2 && text.len - at >= 2 && text.data[at] == 0x84 && text.data[at + 1] == 0xaa) { at += 2; continue; }
        return false;
    }
    return at == text.len;
}

static void clear_json(session_json *fields)
{
    json_object_put(fields->account); json_object_put(fields->arn); json_object_put(fields->user_id);
    json_object_put(fields->code); json_object_put(fields->message); free(fields->cause);
}

static int verify_session(const br_scan_ctx *ctx, const char *id, const char *secret,
                            const char *session, bool retry_403, br_result *result)
{
    char date[17], auth[512], *cause = NULL, *send_error = NULL;
    br_slice redact = {(const unsigned char *)secret, 40};
    if (!ctx) return br_result_set_verification_error(result, "net/http: nil Context", &redact, 1);
    int signed_request = sign_request(id, secret, session, date, auth, &cause);
    if (signed_request) {
        int rc = signed_request < 0 ? -1 : br_result_set_verification_error(result, cause, &redact, 1);
        free(cause);
        return rc;
    }
    const br_header headers[] = {
        {"Accept", "application/json"}, {"Authorization", auth},
        {"x-amz-date", date}, {"x-amz-security-token", session},
    };
    const br_http_request request = {.method = "GET", .url = request_url, .headers = headers, .nheaders = 4,
        .profile = BR_HTTP_SANE, .detector_type = 959};
    br_http_response response = {0};
    session_json fields = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error)) {
        cause = send_error; send_error = NULL;
    } else if (response.status == 403 && retry_403) {
        /* Do not decode, inspect body_error, drain or release the first 403.
         * The native eager-body adapter cannot reproduce this wire workaround. */
        rc = verify_session(ctx, id, secret, session, false, result);
        br_http_release(ctx, &response);
        free(send_error);
        return rc;
    } else if (response.status >= 200 && response.status < 300) {
        int decoded = decode_response(&response, true, &fields);
        if (decoded < 0) rc = -1;
        else if (decoded) { cause = fields.cause; fields.cause = NULL; }
        else if (put_literal(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/aws/") ||
                 put_text(result->extra_data, "account", br_json_text(fields.account)) ||
                 put_text(result->extra_data, "user_id", br_json_text(fields.user_id)) ||
                 put_text(result->extra_data, "arn", br_json_text(fields.arn))) rc = -1;
        else result->verified = true;
    } else if (response.status == 403) {
        int decoded = decode_response(&response, false, &fields);
        if (decoded < 0) rc = -1;
        /* Source uses %v, not %w: this parse wrapper survives unwrapping. */
        else if (decoded) rc = textf(&cause, "couldn't parse the sts response body (%s)", fields.cause);
        else if (!equal_code(br_json_text(fields.code), "invalidclienttokenid") &&
                 !equal_code(br_json_text(fields.code), "expiredtoken"))
            rc = textf(&cause, "request to %s returned status %d with an unexpected reason (%s: %s)", request_url,
                       response.status, json_object_get_string(fields.code) ? json_object_get_string(fields.code) : "",
                       json_object_get_string(fields.message) ? json_object_get_string(fields.message) : "");
    } else rc = textf(&cause, "request to %s returned unexpected status %d", request_url, response.status);
    if (!rc) rc = br_result_set_verification_error(result, cause, &redact, 1);
    br_http_release(ctx, &response);
    clear_json(&fields);
    free(cause); free(send_error);
    return rc;
}

static bool check_session(const char *session, const char *secret)
{
    return (strstr(session, "YXdz") || strstr(session, "Jb3JpZ2luX2Vj")) && !strstr(session, secret);
}

static int make_result(const br_detector *detector, const char *id, const char *secret,
                         br_slice session, br_result *result)
{
    static const unsigned char colon[] = ":";
    if (br_finding_pair_bytes(result, detector->type, (br_slice){(const unsigned char *)id, 20}, "access_key_id",
            (br_slice){(const unsigned char *)secret, 40}, "secret_access_key", (br_slice){colon, 1})) return -1;
    if (session.len > SIZE_MAX - 62) return -1;
    unsigned char *raw = realloc(result->raw_v2.data, 62 + session.len);
    if (!raw) return -1;
    result->raw_v2.data = raw;
    result->raw_v2.data[61] = ':';
    memcpy(result->raw_v2.data + 62, session.data, session.len);
    result->raw_v2.len = 62 + session.len;
    result->redacted = strdup(id);
    result->extra_data = json_object_new_object();
    return result->redacted && result->extra_data ? put_text(result->secret_parts, "session_token", session) : -1;
}

static int scan_session(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AWS session key scan arguments");
    br_aws_options options = {0};
    if (br_aws_read_options(ctx, "invalid AWS session key options", &options, error)) return -1;
    const session_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->secret || !patterns->session)
        return fail(error, "uninitialized AWS session key patterns");
    size_t original_len = out->len;
    br_bytes normalized = {0};
    br_captures ids = {0}, secrets = {0}, sessions = {0};
    int rc = br_aws_replace_url_bytes(input, &normalized, error);
    br_slice data = {normalized.data, normalized.len};
    if (!rc) rc = br_captures_find(patterns->id, data, &ids, true, error);
    if (!rc) rc = br_captures_find(patterns->secret, data, &secrets, true, error);
    if (!rc) rc = br_captures_find(patterns->session, data, &sessions, true, error);
    bool *consumed = !rc ? calloc(sessions.len ? sessions.len : 1, sizeof(*consumed)) : NULL;
    if (!rc && !consumed) rc = fail(error, "out of memory tracking AWS session tokens");
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        const char *id = ids.items[i];
        if (br_ascii_shannon_entropy(br_captures_at(&ids, i)) < 3.0 || br_aws_list_contains(options.skip_ids, id)) continue;
        char account[14];
        bool has_account = br_aws_account_from_id(id, account);
        const char *skip_reason = NULL;
        if (verify && has_account) {
            if (br_aws_list_contains(options.denied_accounts, account)) skip_reason = deny_reason;
            else if (options.allowed_accounts && json_object_array_length(options.allowed_accounts) &&
                     !br_aws_list_contains(options.allowed_accounts, account)) skip_reason = allow_reason;
        }
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            const char *secret = secrets.items[s];
            if (br_ascii_shannon_entropy(br_captures_at(&secrets, s)) < 4.25) continue;
            for (size_t t = 0; !rc && t < sessions.len; ++t) {
                if (consumed[t] || br_ascii_shannon_entropy(br_captures_at(&sessions, t)) < 4.5 ||
                    !check_session(sessions.items[t], secret)) continue;
                br_result result = {0};
                if (make_result(detector, id, secret, br_captures_at(&sessions, t), &result)) rc = -1;
                if (!rc && verify) {
                    br_slice redact = {(const unsigned char *)secret, 40};
                    rc = skip_reason ? br_result_set_verification_error(&result, skip_reason, &redact, 1) :
                        verify_session(ctx, id, secret, sessions.items[t], true, &result);
                }
                if (!rc && !skip_reason && !result.verified && br_aws_hash_like(secret)) {
                    br_result_clear(&result);
                    continue;
                }
                br_json *existing = NULL;
                if (!rc && has_account && !json_object_object_get_ex(result.extra_data, "account", &existing))
                    rc = put_literal(result.extra_data, "account", account);
                bool verified = result.verified;
                if (!rc) rc = br_results_push(out, &result);
                br_result_clear(&result);
                if (rc) { rc = fail(error, "out of memory processing AWS session key"); break; }
                if (verified) {
                    /* delete(sessionMatches, secretMatch) cannot match: secrets
                     * have 40 bytes, session tokens at least 100. Only consume
                     * the token globally; break ONLY this innermost loop. */
                    consumed[t] = true;
                    break;
                }
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(consumed);
    br_captures_clear(&ids); br_captures_clear(&secrets); br_captures_clear(&sessions);
    free(normalized.data);
    return rc;
}

static session_patterns patterns;
static const char *const keywords[] = {"ASIA"};
static const br_detector session_detector = {
    .type = 959, .version = 0, .name = "AWSSessionKey", .custom_name = "",
    .description = "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. "
                   "API keys for AWS can have varying amount of access to these services depending on the IAM policy attached. AWS Session Tokens are short-lived keys.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 2048,
    .state = &patterns, .scan = scan_session, .clean = br_aws_clean, .clean_always = true,
};

int br_aws_session_keys_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AWS session key detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile("\\b((?:ASIA)[A-Z0-9]{16})\\b", &patterns.id, error)) return -1;
    if (!patterns.secret && br_regex_compile(br_aws_secret_pattern, &patterns.secret, error)) return -1;
    if (!patterns.session && br_regex_compile("(?:[^A-Za-z0-9+/]|\\A)([a-zA-Z0-9+/]{100,}={0,3})(?:[^A-Za-z0-9+/=]|\\z)",
                                              &patterns.session, error)) return -1;
    *out = &session_detector;
    return 0;
}
