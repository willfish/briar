/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/alibaba/alibaba.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *id; } alibaba_patterns;
typedef struct { br_json *message, *code; char *cause; } alibaba_reply;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Go QueryEscape: form spaces use '+', and hex digits are uppercase. */
static int query_escape(const char *input, char *out, size_t cap)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t at = 0;
    for (const unsigned char *p = (const unsigned char *)input; *p; ++p) {
        unsigned char c = *p;
        bool literal = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || strchr("-_.~", c);
        size_t needed = literal || c == ' ' ? 1 : 3;
        if (cap - at <= needed) return -1;
        if (literal) out[at++] = (char)c;
        else if (c == ' ') out[at++] = '+';
        else { out[at++] = '%'; out[at++] = hex[c >> 4]; out[at++] = hex[c & 15]; }
    }
    out[at] = '\0';
    return (int)at;
}

static int encode_query(const char *id, const char *timestamp, const char *nonce,
                         const char *signature, char *out, size_t cap)
{
    /* url.Values.Encode sorts parameter names; Signature is omitted before signing. */
    const struct { const char *name, *value; } params[] = {
        {"AccessKeyId", id}, {"Action", "DescribeRegions"}, {"Format", "JSON"},
        {"Signature", signature}, {"SignatureMethod", "HMAC-SHA1"},
        {"SignatureNonce", nonce}, {"SignatureVersion", "1.0"},
        {"Timestamp", timestamp}, {"Version", "2014-05-26"},
    };
    size_t at = 0;
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); ++i) {
        if (!params[i].value) continue;
        int n = snprintf(out + at, cap - at, "%s%s=", at ? "&" : "", params[i].name);
        if (n < 0 || (size_t)n >= cap - at) return -1;
        at += (size_t)n;
        n = query_escape(params[i].value, out + at, cap - at);
        if (n < 0) return -1;
        at += (size_t)n;
    }
    return (int)at;
}

static int string_to_sign(const char *query, char *out, size_t cap)
{
    char canonical[512];
    size_t at = 0;
    for (const char *p = query; *p;) {
        const char *replacement;
        size_t consumed;
        char literal[2] = {*p, '\0'};
        if (*p == '+') { replacement = "%20"; consumed = 1; }
        else if (!strncmp(p, "%7E", 3)) { replacement = "~"; consumed = 3; }
        else if (*p == '*') { replacement = "%2A"; consumed = 1; }
        else { replacement = literal; consumed = 1; }
        size_t len = strlen(replacement);
        if (sizeof(canonical) - at <= len) return -1;
        memcpy(canonical + at, replacement, len);
        at += len;
        p += consumed;
    }
    canonical[at] = '\0';
    static const char prefix[] = "GET&%2F&";
    if (cap < sizeof(prefix)) return -1;
    memcpy(out, prefix, sizeof(prefix) - 1);
    return query_escape(canonical, out + sizeof(prefix) - 1, cap - sizeof(prefix) + 1) < 0 ? -1 : 0;
}

static int signed_url(const char *key, const char *id, char *url, size_t cap, size_t *query_len)
{
    time_t now = time(NULL);
    struct tm utc;
    char timestamp[32];
    if (!gmtime_r(&now, &utc) ||
        !strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc)) return -1;
    static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    unsigned char random[16] = {0};
    char nonce[17];
    /* Go rand.Read supplies a full secure buffer or terminates; OpenSSL may fail. */
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    for (size_t i = 0; i < sizeof(random); ++i) nonce[i] = alphabet[random[i] % 36];
    nonce[16] = '\0';

    /* Bounds follow the 30-byte secret, 21..25-byte ID and fixed request fields. */
    char query[512], input[3 * sizeof(query) + sizeof("GET&%2F&")], signing_key[32];
    if (encode_query(id, timestamp, nonce, NULL, query, sizeof(query)) < 0 ||
        string_to_sign(query, input, sizeof(input)) != 0) return -1;
    snprintf(signing_key, sizeof(signing_key), "%s&", key);
    unsigned char digest[20], signature[29];
    size_t digest_len = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA1", NULL, signing_key, strlen(signing_key),
                   (const unsigned char *)input, strlen(input), digest, sizeof(digest), &digest_len) ||
        digest_len != sizeof(digest) || EVP_EncodeBlock(signature, digest, sizeof(digest)) != 28)
        return -1;
    int n = encode_query(id, timestamp, nonce, (const char *)signature, query, sizeof(query));
    if (n < 0) return -1;
    *query_len = (size_t)n;
    n = snprintf(url, cap, "https://ecs.aliyuncs.com?%s", query);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}

static int response_member(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    alibaba_reply *reply = user;
    const char *field;
    br_json **destination = NULL;
    if (br_json_field_name(name, "requestid")) field = "alibabaResp.RequestId";
    else if (br_json_field_name(name, "message")) {
        field = "alibabaResp.Message"; destination = &reply->message;
    } else if (br_json_field_name(name, "recommend")) field = "alibabaResp.Recommend";
    else if (br_json_field_name(name, "hostid")) field = "alibabaResp.HostId";
    else if (br_json_field_name(name, "code")) {
        field = "alibabaResp.Code"; destination = &reply->code;
    } else return 0;
    if (value && !json_object_is_type(value, json_type_string))
        return br_json_type_cause(value, field, "string", &reply->cause) == 0 ? 1 : -1;
    /* JSON null leaves an existing Go string unchanged, including on duplicates. */
    if (value && destination) {
        json_object_put(*destination);
        *destination = json_object_get(value);
    }
    return 0;
}

static int decode_response(const br_http_response *response, alibaba_reply *reply)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &reply->cause);
    if (!rc && root) {
        if (!json_object_is_type(root, json_type_object))
            rc = br_json_type_cause(root, NULL, "alibaba.alibabaResp", &reply->cause) == 0 ? 1 : -1;
        else rc = br_json_each_member((br_slice){response->body.data, end}, response_member, reply);
    }
    json_object_put(root);
    return rc;
}

static int status_cause(int status, alibaba_reply *reply)
{
    char prefix[80];
    int n = snprintf(prefix, sizeof(prefix), "unexpected HTTP response status %d", status);
    br_slice message = br_json_text(reply->message), code = br_json_text(reply->code);
    if (!message.len) {
        reply->cause = strdup(prefix);
        return reply->cause ? 0 : -1;
    }
    size_t fixed = (size_t)n + 5; /* ': ', ', ', and the terminator. */
    if (message.len > SIZE_MAX - fixed || code.len > SIZE_MAX - fixed - message.len) return -1;
    reply->cause = malloc(fixed + message.len + code.len);
    if (!reply->cause) return -1;
    char *at = reply->cause;
    memcpy(at, prefix, (size_t)n); at += n;
    memcpy(at, ": ", 2); at += 2;
    memcpy(at, message.data, message.len); at += message.len;
    memcpy(at, ", ", 2); at += 2;
    memcpy(at, code.data, code.len); at[code.len] = '\0';
    return 0;
}

static int verification_error(br_result *result, const char *cause)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int verify_alibaba(const br_scan_ctx *ctx, const char *key,
                           const char *id, br_result *result)
{
    char url[sizeof("https://ecs.aliyuncs.com?") + 512], length[24];
    size_t query_len;
    if (signed_url(key, id, url, sizeof(url), &query_len) != 0)
        return verification_error(result, "cannot construct Alibaba signed request");
    snprintf(length, sizeof(length), "%zu", query_len);
    const br_header headers[] = {
        {"Content-Type", "text/xml;charset=utf-8"}, {"Content-Length", length},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 0,
    };
    br_http_response response = {0};
    alibaba_reply reply = {0};
    int rc;
    if (br_http_send(ctx, &request, &response, &reply.cause) != 0) {
        rc = verification_error(result, reply.cause ? reply.cause : "HTTP transport failed");
    } else {
        /* Even rejection statuses must first decode the five-string response. */
        rc = decode_response(&response, &reply);
        if (rc == 0) {
            switch (response.status) {
            case 200: result->verified = true; break;
            case 400:
            case 404: break;
            default: rc = status_cause(response.status, &reply); break;
            }
        }
        if (rc >= 0) rc = verification_error(result, reply.cause);
    }
    br_http_release(ctx, &response);
    json_object_put(reply.message);
    json_object_put(reply.code);
    free(reply.cause);
    return rc;
}

static int scan_alibaba(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Alibaba scan arguments");
    const alibaba_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return fail(error, "uninitialized Alibaba detector");
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, error);
    /* Both alphabets exclude whitespace. Preserve duplicate occurrences and the
     * source's key-outer/ID-inner product; engine span limits do not apply here. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0 ||
                (verify && verify_alibaba(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Alibaba result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static alibaba_patterns patterns;
static const char *const keywords[] = {"LTAI"};
static const br_detector alibaba = {
    .type = 0, .version = 0, .name = "Alibaba", .custom_name = "",
    .description = "Alibaba Cloud is a cloud computing service that provides a suite of cloud "
                   "computing services including data storage, relational databases, big-data "
                   "processing, and content delivery networks (CDNs). Alibaba Cloud API keys "
                   "can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_alibaba,
};

int br_alibaba_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Alibaba detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile("\\b([a-zA-Z0-9]{30})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id && br_regex_compile("\\b(LTAI[a-zA-Z0-9]{17,21})[\"';\\s]*", &patterns.id, error) != 0)
        return -1;
    *out = &alibaba;
    return 0;
}
