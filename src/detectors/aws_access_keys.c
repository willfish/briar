/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aws/access_keys, aws/common.go,
 * aws/utils.go and detectors/account_filter.go. AWS Query/XML and SigV4 behavior
 * from STS 1.45.7, SNS 1.42.7, SDK 1.43.7 and Smithy 1.27.9 is modified and
 * reimplemented in C; see NOTICE and LICENSES/Apache-2.0.txt. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <libxml/parser.h>
#include <libxml/SAX2.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static const char deny_reason[] = "Account ID is in the deny list for verification";
static const char allow_reason[] = "Account ID is not in the allow list for verification";
static const char thinkst_message[] = "This is an AWS canary token generated at canarytokens.org.";
static const char knockoff_message[] = "This is an off brand AWS Canary inspired by canarytokens.org.";
static const char *const thinkst_accounts[] = {
    "052310077262", "171436882533", "534261010715", "595918472158", "717712589309",
    "819147034852", "992382622183", "730335385048", "266735846894", "893192397702",
};
static const char *const knockoff_accounts[] = {
    "044858866125", "251535659677", "344043088457", "351906852752", "390477818340",
    "426127672474", "427150556519", "439872796651", "445142720921", "465867158099",
    "637958123769", "693412236332", "732624840810", "735421457923", "959235150393", "982842642351",
};

typedef struct { br_regex *id, *secret; } aws_patterns;
typedef struct { br_json *skip_ids, *allowed_accounts, *denied_accounts; } aws_options;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int option_list(const br_json *options, const char *name, br_json **out, char **error)
{
    *out = NULL;
    if (!options || !json_object_object_get_ex(options, name, out) || !*out) return 0;
    bool valid = json_object_is_type(*out, json_type_array);
    for (size_t i = 0; valid && i < json_object_array_length(*out); ++i)
        valid = json_object_is_type(json_object_array_get_idx(*out, i), json_type_string);
    if (valid) return 0;
    char message[128];
    snprintf(message, sizeof(message), "invalid AWS access key options: %s must be an array of strings", name);
    return fail(error, message);
}

static int read_options(const br_scan_ctx *ctx, aws_options *options, char **error)
{
    const br_json *value = ctx ? ctx->options : NULL;
    if (value && !json_object_is_type(value, json_type_object))
        return fail(error, "invalid AWS access key options: expected an object");
    if (option_list(value, "skip_ids", &options->skip_ids, error) != 0 ||
        option_list(value, "allowed_accounts", &options->allowed_accounts, error) != 0 ||
        option_list(value, "denied_accounts", &options->denied_accounts, error) != 0) return -1;
    return 0;
}

static bool list_contains(br_json *list, const char *text)
{
    size_t len = strlen(text), count = list ? json_object_array_length(list) : 0;
    for (size_t i = 0; i < count; ++i) {
        br_json *item = json_object_array_get_idx(list, i);
        if ((size_t)json_object_get_string_len(item) == len && !memcmp(json_object_get_string(item), text, len))
            return true;
    }
    return false;
}

/* Only the six pinned replacements, left to right without recursive decoding. */
static int replace_url_bytes(br_slice input, br_bytes *out, char **error)
{
    out->data = malloc(input.len ? input.len : 1);
    if (!out->data) return fail(error, "out of memory replacing AWS URL bytes");
    for (size_t i = 0; i < input.len; ++i) {
        unsigned char replacement = 0;
        if (input.data[i] == '%' && input.len - i >= 3) {
            unsigned char a = input.data[i + 1], b = input.data[i + 2];
            if (a == '2' && (b == 'B' || b == 'b')) replacement = '+';
            else if (a == '2' && (b == 'F' || b == 'f')) replacement = '/';
            else if (a == '3' && (b == 'D' || b == 'd')) replacement = '=';
        }
        if (replacement) { out->data[out->len++] = replacement; i += 2; }
        else out->data[out->len++] = input.data[i];
    }
    return 0;
}

static bool account_from_id(const char *id, char account[14])
{
    if (id[4] == 'I' || id[4] == 'J') return false;
    unsigned char decoded[10];
    unsigned buffer = 0, bits = 0;
    size_t count = 0;
    for (size_t i = 4; i < 20; ++i) {
        unsigned char c = (unsigned char)id[i];
        unsigned value;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else return false;
        buffer = (buffer << 5) | value;
        bits += 5;
        if (bits >= 8) { bits -= 8; decoded[count++] = (unsigned char)(buffer >> bits); }
        buffer &= (1u << bits) - 1;
    }
    if (count < 6) return false;
    uint64_t z = 0;
    for (size_t i = 0; i < 6; ++i) z = (z << 8) | decoded[i];
    uint64_t number = (z & UINT64_C(0x7fffffffff80)) >> 7;
    snprintf(account, 14, "%012" PRIu64, number); /* Minimum width, not truncation. */
    return true;
}

static bool known_account(const char *account, const char *const *list, size_t count)
{
    for (size_t i = 0; i < count; ++i) if (!strcmp(account, list[i])) return true;
    return false;
}

static int put_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int make_result(const br_detector *detector, const char *id, const char *secret,
                        const char *account, br_result *result)
{
    static const unsigned char colon[] = ":";
    if (br_finding_pair_bytes(result, detector->type, (br_slice){(const unsigned char *)id, 20}, "access_key_id",
            (br_slice){(const unsigned char *)secret, 40}, "secret_access_key", (br_slice){colon, 1}) != 0) return -1;
    result->redacted = strdup(id);
    result->extra_data = json_object_new_object();
    const char *resource = !strncmp(id, "AKIA", 4) ? "Access key" :
                           !strncmp(id, "ABIA", 4) ? "AWS STS service bearer token" : "Context-specific credential";
    if (!result->redacted || !result->extra_data || put_text(result->extra_data, "resource_type", resource) != 0) return -1;
    if (account) {
        if (put_text(result->extra_data, "account", account) != 0) return -1;
        bool thinkst = known_account(account, thinkst_accounts, sizeof(thinkst_accounts) / sizeof(thinkst_accounts[0]));
        bool knockoff = known_account(account, knockoff_accounts, sizeof(knockoff_accounts) / sizeof(knockoff_accounts[0]));
        if (thinkst && put_text(result->extra_data, "message", thinkst_message) != 0) return -1;
        if (knockoff && put_text(result->extra_data, "message", knockoff_message) != 0) return -1;
        if ((thinkst || knockoff) && put_text(result->extra_data, "is_canary", "true") != 0) return -1;
    }
    return 0;
}

/* Only these two SDK operations are implemented. No host configuration,
 * credential discovery, SDK environment loading, or native profile fallback. */
typedef struct {
    char *account, *user_id, *arn, *code, *message, *request_id;
    bool typed;
} aws_reply;

static void clear_reply(aws_reply *reply)
{
    free(reply->account); free(reply->user_id); free(reply->arn);
    free(reply->code); free(reply->message); free(reply->request_id);
    memset(reply, 0, sizeof(*reply));
}

static int textf(char **out, const char *format, ...)
{
    va_list args, copy;
    va_start(args, format);
    va_copy(copy, args);
    int len = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    *out = len < 0 ? NULL : malloc((size_t)len + 1);
    if (*out) vsnprintf(*out, (size_t)len + 1, format, args);
    va_end(args);
    return *out ? 0 : -1;
}

static int cause_text(char **cause, const char *text)
{
    *cause = strdup(text);
    return *cause ? 1 : -1;
}

static bool named(xmlNode *node, const char *name, bool fold)
{
    return node->type == XML_ELEMENT_NODE &&
        (fold ? !xmlStrcasecmp(node->name, BAD_CAST name) : !xmlStrcmp(node->name, BAD_CAST name));
}

/* Keep the standard libxml2 tree builder, but retain CDATA event multiplicity
 * on each containing element: DOM nodes alone may merge adjacent sections or
 * drop empty ones. These markers own no memory and are never dereferenced. */
static char single_cdata, multiple_cdata;

static void cdata_event(void *user, const xmlChar *value, int len)
{
    xmlParserCtxt *parser = user;
    xmlNode *parent = parser->node;
    if (parent) parent->_private = parent->_private ? &multiple_cdata : &single_cdata;
    xmlSAX2CDataBlock(user, value, len);
}

/* Smithy Value accepts one CharData token or an empty element, not nested
 * elements, comments or additional text events. Never flatten node content. */
static int xml_text(xmlNode *node, char **out, char **cause)
{
    xmlNode *child = node->children;
    if (node->_private == &multiple_cdata || (node->_private == &single_cdata && child && child->type != XML_CDATA_SECTION_NODE))
        return cause_text(cause, "unsupported: AWS XML simple-value token shape");
    if (child && (child->next || (child->type != XML_TEXT_NODE && child->type != XML_CDATA_SECTION_NODE)))
        return cause_text(cause, "unsupported: AWS XML simple-value token shape");
    char *value = strdup(child && child->content ? (const char *)child->content : "");
    if (!value) return -1;
    free(*out);
    *out = value;
    return 0;
}

static xmlNode *child_named(xmlNode *parent, const char *name, bool fold)
{
    for (xmlNode *n = parent->children; n; n = n->next) if (named(n, name, fold)) return n;
    return NULL;
}

/* 0 decoded; 1 explicit unsupported decode cause; -1 resource failure.
 * Empty successful bodies are left as nil fields, matching SDK output. */
static int decode_reply(const br_http_response *response, bool sns, aws_reply *reply, char **cause)
{
    if (response->body_error)
        return cause_text(cause, "unsupported: AWS XML read-error/streaming semantics");
    bool empty = true;
    for (size_t i = 0; i < response->body.len; ++i) {
        unsigned char ch = response->body.data[i];
        if (ch != ' ' && ch != '\r' && ch != '\n' && ch != '\t') { empty = false; break; }
    }
    bool success = response->status >= 200 && response->status < 300;
    if (response->body.len > INT_MAX) return cause_text(cause, "unsupported: AWS XML body size");
    xmlDoc *doc = NULL;
    xmlNode *root = NULL;
    if (!empty) {
        xmlParserCtxt *parser = xmlNewParserCtxt();
        if (!parser) return -1;
        parser->sax->cdataBlock = cdata_event;
        /* The SDK leaves Go's CharsetReader nil: never auto-transcode or
         * silently accept a non-UTF-8 declaration, even for ASCII content. */
        doc = xmlCtxtReadMemory(parser, (const char *)response->body.data, (int)response->body.len, NULL, "UTF-8",
                               XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NO_XXE);
        const xmlChar *declared = xmlCtxtGetDeclaredEncoding(parser);
        bool unsupported_encoding = declared && xmlStrcasecmp(declared, BAD_CAST "UTF-8");
        xmlFreeParserCtxt(parser);
        if (unsupported_encoding) {
            xmlFreeDoc(doc);
            return cause_text(cause, "unsupported: AWS XML encoding");
        }
        if (!doc) return cause_text(cause, "unsupported: AWS XML syntax/streaming diagnostics");
        if (doc->intSubset || doc->extSubset) {
            xmlFreeDoc(doc);
            return cause_text(cause, "unsupported: AWS XML DTD");
        }
        root = xmlDocGetRootElement(doc);
    }
    int rc = 0;
    if (success && root) {
        const char *result_name = sns ? "PublishResult" : "GetCallerIdentityResult";
        xmlNode *result = child_named(root, result_name, true);
        if (!result) {
            if (textf(cause, "%s node not found", result_name) != 0) rc = -1;
            else rc = 1;
        }
        for (xmlNode *n = result ? result->children : NULL; !rc && n; n = n->next) {
            char **field = !sns && named(n, "Account", true) ? &reply->account :
                           !sns && named(n, "UserId", true) ? &reply->user_id :
                           !sns && named(n, "Arn", true) ? &reply->arn : NULL;
            if (field) rc = xml_text(n, field, cause);
            else if (sns && (named(n, "MessageId", true) || named(n, "SequenceNumber", true))) {
                char *ignored = NULL;
                rc = xml_text(n, &ignored, cause);
                free(ignored);
            }
        }
    } else if (!success) {
        /* The generic error extractor uses encoding/xml struct tags (case
         * sensitive), unlike Smithy's case-folded success/typed-error fields. */
        xmlNode *first_error = root ? child_named(root, "Error", true) : NULL;
        for (xmlNode *n = root ? root->children : NULL; !rc && n; n = n->next) {
            if (named(n, "RequestId", false)) rc = xml_text(n, &reply->request_id, cause);
            if (!named(n, "Error", false)) continue;
            for (xmlNode *e = n->children; !rc && e; e = e->next) {
                if (named(e, "Code", false)) rc = xml_text(e, &reply->code, cause);
                else if (named(e, "Message", false)) rc = xml_text(e, &reply->message, cause);
            }
        }
        static const char *const typed_sns[] = {
            "AuthorizationError", "EndpointDisabled", "InternalError", "InvalidParameter", "InvalidSecurity",
            "KMSAccessDenied", "KMSDisabled", "KMSInvalidState", "KMSNotFound", "KMSOptInRequired", "KMSThrottling",
            "NotFound", "ParameterValueInvalid", "PlatformApplicationDisabled", "ValidationException",
        };
        if (!rc && sns && reply->code) {
            for (size_t i = 0; i < sizeof(typed_sns) / sizeof(typed_sns[0]); ++i) {
                if (strcasecmp(reply->code, typed_sns[i])) continue;
                free(reply->code);
                reply->code = strdup(typed_sns[i]);
                free(reply->message);
                reply->message = NULL;
                reply->typed = true;
                if (!reply->code) { rc = -1; break; }
                if (!first_error) { rc = cause_text(cause, "unsupported: AWS typed error envelope"); break; }
                for (xmlNode *e = first_error->children; !rc && e; e = e->next)
                    if (named(e, "message", true)) rc = xml_text(e, &reply->message, cause);
                break;
            }
        }
        if (!rc && (!reply->code || !*reply->code)) {
            free(reply->code); reply->code = strdup("UnknownError");
            if (!reply->code) rc = -1;
        }
        if (!rc && (!reply->message || (!reply->typed && !*reply->message))) {
            free(reply->message); reply->message = strdup(reply->typed ? "" : "UnknownError");
            if (!reply->message) rc = -1;
        }
    }
    xmlFreeDoc(doc);
    return rc;
}

static const char *response_header(const br_http_response *response, const char *name)
{
    for (size_t i = 0; i < response->nheaders; ++i)
        if (!strcasecmp(response->headers[i].name, name)) return response->headers[i].value;
    return NULL;
}

static int sha256_hex(const void *data, size_t len, char out[65])
{
    unsigned char hash[32];
    size_t count = 0;
    if (!EVP_Q_digest(NULL, "SHA256", NULL, data, len, hash, &count) || count != 32) return -1;
    for (size_t i = 0; i < 32; ++i) snprintf(out + 2 * i, 3, "%02x", hash[i]);
    return 0;
}

static int hmac256(const void *key, size_t len, const char *value, unsigned char out[32])
{
    size_t count = 0;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, len,
                     (const unsigned char *)value, strlen(value), out, 32, &count) && count == 32 ? 0 : -1;
}

static int invocation_id(char out[37])
{
    unsigned char raw[16];
    if (RAND_bytes(raw, 16) != 1) return -1;
    raw[6] = (raw[6] & 15) | 64;
    raw[8] = (raw[8] & 63) | 128;
    size_t at = 0;
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[at++] = '-';
        snprintf(out + at, 3, "%02x", raw[i]); at += 2;
    }
    return 0;
}

static int authorization(const char *id, const char *secret, const char *service, const char *uuid,
                          const char *attempt, const char *body, time_t now, char date[17], char out[512])
{
    struct tm utc;
    if (!gmtime_r(&now, &utc) || strftime(date, 17, "%Y%m%dT%H%M%SZ", &utc) != 16) return -1;
    char day[9]; memcpy(day, date, 8); day[8] = '\0';
    static const char signed_headers[] = "amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-date";
    char payload_hash[65], canonical[1024], canonical_hash[65], scope[80], to_sign[256];
    if (sha256_hex(body, strlen(body), payload_hash) != 0) return -1;
    snprintf(canonical, sizeof(canonical),
        "POST\n/\n\namz-sdk-invocation-id:%s\namz-sdk-request:%s\ncontent-length:%zu\n"
        "content-type:application/x-www-form-urlencoded\nhost:%s.us-east-1.amazonaws.com\nx-amz-date:%s\n\n%s\n%s",
        uuid, attempt, strlen(body), service, date, signed_headers, payload_hash);
    if (sha256_hex(canonical, strlen(canonical), canonical_hash) != 0) return -1;
    snprintf(scope, sizeof(scope), "%s/us-east-1/%s/aws4_request", day, service);
    snprintf(to_sign, sizeof(to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", date, scope, canonical_hash);
    char key[45]; snprintf(key, sizeof(key), "AWS4%s", secret);
    unsigned char k_date[32], k_region[32], k_service[32], k_signing[32], signature[32];
    if (hmac256(key, strlen(key), day, k_date) || hmac256(k_date, 32, "us-east-1", k_region) ||
        hmac256(k_region, 32, service, k_service) || hmac256(k_service, 32, "aws4_request", k_signing) ||
        hmac256(k_signing, 32, to_sign, signature)) return -1;
    char hex[65];
    for (size_t i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", signature[i]);
    int len = snprintf(out, 512, "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", id, scope, signed_headers, hex);
    return len > 0 && len < 512 ? 0 : -1;
}

static bool retry_code(const char *code, bool sns)
{
    static const char *const codes[] = {
        "RequestTimeout", "RequestTimeoutException", "Throttling", "ThrottlingException", "ThrottledException",
        "RequestThrottledException", "TooManyRequestsException", "ProvisionedThroughputExceededException",
        "TransactionInProgressException", "RequestLimitExceeded", "BandwidthLimitExceeded", "LimitExceededException",
        "RequestThrottled", "SlowDown", "PriorRequestNotComplete", "EC2ThrottledException",
    };
    return known_account(code, codes, sizeof(codes) / sizeof(codes[0])) || (!sns && !strcmp(code, "IDPCommunicationError"));
}

static bool skew_code(const char *code)
{
    static const char *const codes[] = {"InvalidSignatureException", "SignatureDoesNotMatch", "AuthFailure", "RequestTimeTooSkewed", "AccessDeniedException"};
    return known_account(code, codes, sizeof(codes) / sizeof(codes[0]));
}

static const char *interrupted(const br_scan_ctx *ctx)
{
    if (!ctx) return NULL;
    if (ctx->cancelled && ctx->cancelled(ctx->cancel_user)) return "context canceled";
    if (ctx->deadline_monotonic_ms) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return "unsupported: AWS deadline clock unavailable";
        if ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 >= ctx->deadline_monotonic_ms) return "context deadline exceeded";
    }
    return NULL;
}

static int retry_wait(const br_scan_ctx *ctx, unsigned attempt, char **cause)
{
    /* Legacy SDK jitter: a uniform 53-bit fraction times 2^attempt seconds.
     * The fresh default 500-token bucket cannot exhaust in three attempts.
     * Custom/adaptive/2026 retry modes and Retry-After remain scope gaps. */
    unsigned char raw[7];
    if (RAND_bytes(raw, 7) != 1) return cause_text(cause, "unsupported: AWS retry randomness failed");
    uint64_t fraction = raw[0] & 31;
    for (size_t i = 1; i < 7; ++i) fraction = (fraction << 8) | raw[i];
    uint64_t ns = (uint64_t)((double)fraction / 9007199254740992.0 * (1u << attempt) * 1000000000.0);
    while (ns) {
        const char *stop = interrupted(ctx);
        if (stop) return cause_text(cause, stop);
        uint64_t step = ns > 50000000 ? 50000000 : ns;
        struct timespec delay = {0, (long)step};
        while (nanosleep(&delay, &delay)) {
            if (errno != EINTR) return cause_text(cause, "unsupported: AWS retry sleep failed");
            stop = interrupted(ctx);
            if (stop) return cause_text(cause, stop);
        }
        ns -= step;
    }
    return 0;
}

/* 0 SDK success; 1 API error; 2 guarded/transport cause; -1 resource failure.
 * Reply/cause/full_error are owned. Native BR_HTTP_AWS rejects before I/O. */
static int sdk_call(const br_scan_ctx *ctx, bool sns, const char *id, const char *secret,
                     aws_reply *reply, char **full_error, char **cause)
{
    const char *service = sns ? "sns" : "sts";
    const char *body = sns ? "Action=Publish&Message=foo&PhoneNumber=1&Version=2010-03-31" : "Action=GetCallerIdentity&Version=2011-06-15";
    const char *url = sns ? "https://sns.us-east-1.amazonaws.com/" : "https://sts.us-east-1.amazonaws.com/";
    char uuid[37];
    if (invocation_id(uuid) != 0) return cause_text(cause, "unsupported: AWS invocation randomness failed") < 0 ? -1 : 2;
    int64_t skew = 0; /* SDK time.Duration, nanoseconds. */
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        if (skew > 0 && ctx && ctx->deadline_monotonic_ms)
            return cause_text(cause, "unsupported: AWS skew-adjusted deadline/TTL timing") < 0 ? -1 : 2;
        char date[17], auth[512], metric[32], length[8];
        snprintf(metric, sizeof(metric), "attempt=%u; max=3", attempt);
        snprintf(length, sizeof(length), "%zu", strlen(body));
        struct timespec before, after;
        if (clock_gettime(CLOCK_REALTIME, &before) || before.tv_sec < 0 || before.tv_sec > INT64_MAX / 1000000000)
            return cause_text(cause, "unsupported: AWS signing clock unavailable") < 0 ? -1 : 2;
        int64_t start = (int64_t)before.tv_sec * 1000000000 + before.tv_nsec;
        if ((skew > 0 && start > INT64_MAX - skew) || (skew < 0 && start < -skew) ||
            authorization(id, secret, service, uuid, metric, body, (time_t)((start + skew) / 1000000000), date, auth))
            return cause_text(cause, "unsupported: AWS signing clock or crypto failure") < 0 ? -1 : 2;
        const br_header headers[] = {
            {"Content-Type", "application/x-www-form-urlencoded"}, {"Content-Length", length},
            {"Amz-Sdk-Invocation-Id", uuid}, {"Amz-Sdk-Request", metric}, {"X-Amz-Date", date}, {"Authorization", auth},
        };
        const br_http_request request = {.method = "POST", .url = url, .headers = headers, .nheaders = 6,
            .body = {(const unsigned char *)body, strlen(body)}, .profile = BR_HTTP_AWS, .detector_type = 2};
        br_http_response response = {0};
        char *transport_error = NULL;
        int sent = br_http_send(ctx, &request, &response, &transport_error);
        bool clock_ok = !clock_gettime(CLOCK_REALTIME, &after) && after.tv_sec >= 0 && after.tv_sec <= INT64_MAX / 1000000000;
        if (sent) {
            br_http_release(ctx, &response);
            *cause = transport_error ? transport_error : strdup("HTTP transport failed");
            return *cause ? 2 : -1; /* String-only ABI errors cannot classify SDK connection retries. */
        }
        free(transport_error);
        int decoded = decode_reply(&response, sns, reply, cause);
        int status = response.status;
        int64_t next_skew = 0;
        bool candidate = false;
        const char *date_header = response_header(&response, "Date");
        const char *age = response_header(&response, "Age");
        if (date_header && (!age || !*age) && clock_ok) {
            int64_t end = (int64_t)after.tv_sec * 1000000000 + after.tv_nsec;
            time_t server = curl_getdate(date_header, NULL);
            /* Only ordinary RFC1123 GMT dates are evidenced here. Other Go
             * ParseTime formats, wall-clock jumps and long RTTs stay guarded. */
            if (strlen(date_header) != 29 || strcmp(date_header + 25, " GMT") || end < start || end - start > INT64_C(900000000000)) {
                if (!decoded) decoded = cause_text(cause, "unsupported: AWS response Date/timing shape");
            } else if (server >= 0 && server <= INT64_MAX / 1000000000) {
                next_skew = (int64_t)server * 1000000000 - (start + (end - start) / 2);
                candidate = true;
            }
        }
        const char *request_id = response_header(&response, "X-Amzn-Requestid");
        if (!request_id || !*request_id) request_id = response_header(&response, "X-Amz-RequestId");
        if (request_id && *request_id) {
            free(reply->request_id); reply->request_id = strdup(request_id);
            if (!reply->request_id) decoded = -1;
        }
        br_http_release(ctx, &response);
        if (decoded) return decoded < 0 ? -1 : 2;
        if (status >= 200 && status < 300) return 0;
        bool retry = status == 500 || status == 502 || status == 503 || status == 504 || retry_code(reply->code, sns);
        if (candidate && skew_code(reply->code) &&
            (next_skew - skew > INT64_C(240000000000) || skew - next_skew > INT64_C(240000000000))) retry = true;
        if (retry && attempt < 3) {
            clear_reply(reply);
            int wait = retry_wait(ctx, attempt, cause);
            if (wait) return wait < 0 ? -1 : 2;
            skew = candidate ? next_skew : 0;
            continue;
        }
        if (textf(cause, "%s%s: %s", reply->typed ? "" : "api error ", reply->code, reply->message) != 0) return -1;
        if (textf(full_error, "operation error %s: %s, https response error StatusCode: %d, RequestID: %s, %s",
                  sns ? "SNS" : "STS", sns ? "Publish" : "GetCallerIdentity", status,
                  reply->request_id ? reply->request_id : "", *cause) != 0) return -1;
        return 1;
    }
    return -1;
}

/* 1 means a source panic shape: caller must roll back this invocation only. */
static int verify_pair(const br_scan_ctx *ctx, bool sns, const char *id, const char *secret,
                        bool retry_403, br_result *result, char **panic_cause)
{
    for (unsigned invocation = 0; invocation < 2; ++invocation) {
        aws_reply reply = {0};
        char *full_error = NULL, *cause = NULL;
        int outcome = sdk_call(ctx, sns, id, secret, &reply, &full_error, &cause);
        int rc = 0;
        if (!outcome) {
            if (sns || !reply.account || !reply.user_id || !reply.arn) {
                *panic_cause = strdup(sns ? "unsupported upstream panic: AWS SNS Publish returned nil error" :
                    "unsupported upstream panic: AWS STS response has nil identity fields");
                rc = *panic_cause ? 1 : -1;
            } else if (put_text(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/aws/") ||
                       put_text(result->extra_data, "account", reply.account) || put_text(result->extra_data, "user_id", reply.user_id) ||
                       put_text(result->extra_data, "arn", reply.arn)) rc = -1;
            else result->verified = true;
        } else if (outcome < 0) rc = -1;
        else if (outcome == 1 && !sns && strstr(full_error, "StatusCode: 403")) {
            if (retry_403 && !invocation) {
                clear_reply(&reply); free(full_error); free(cause);
                continue; /* A new SDK invocation has a new UUID and attempt=1. */
            }
            free(cause); cause = NULL;
        } else if (outcome == 1 && sns && strstr(full_error, "not authorized to perform")) {
            const char *start = strstr(full_error, "User: ");
            if (!start) {
                *panic_cause = strdup("unsupported upstream panic: AWS canary denial lacks User: ");
                rc = *panic_cause ? 1 : -1;
            } else {
                start += 6;
                const char *end = strstr(start, " is not authorized to perform: ");
                char *arn = strndup(start, end ? (size_t)(end - start) : strlen(start));
                if (!arn || (*arn && put_text(result->extra_data, "arn", arn))) rc = -1;
                else result->verified = true;
                free(arn);
                free(cause); cause = NULL;
            }
        } else if (outcome == 1 && (strstr(full_error, "InvalidClientTokenId") ||
                   (sns && (strstr(full_error, "does not match the signature you provided") || strstr(full_error, "status code: 403"))))) {
            free(cause); cause = NULL;
        }
        /* SDK and detector wrappers unwrap to the API error before redaction.
         * The ID is deliberately not included in the redaction list. */
        if (!rc) {
            br_slice value = {(const unsigned char *)secret, 40};
            rc = br_result_set_verification_error(result, cause, &value, 1);
        }
        clear_reply(&reply); free(full_error); free(cause);
        return rc;
    }
    return -1;
}

static bool hash_like(const char *secret)
{
    /* Captures are exactly 40 bytes, so the unanchored [a-f0-9]{40} match is
     * equivalent to checking the entire capture. Keep this after verification. */
    for (size_t i = 0; i < 40; ++i)
        if (!((secret[i] >= 'a' && secret[i] <= 'f') || (secret[i] >= '0' && secret[i] <= '9'))) return false;
    return true;
}

static int scan_aws(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AWS access key scan arguments");
    aws_options options = {0};
    if (read_options(ctx, &options, error) != 0) return -1;
    const aws_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->secret) return fail(error, "uninitialized AWS access key patterns");
    size_t original_len = out->len;
    br_bytes replaced = {0};
    br_captures ids = {0}, secrets = {0};
    int rc = replace_url_bytes(input, &replaced, error);
    br_slice normalized = {replaced.data, replaced.len};
    if (!rc) rc = br_captures_find(compiled->id, normalized, &ids, true, error);
    if (!rc) rc = br_captures_find(compiled->secret, normalized, &secrets, true, error);
    bool *consumed = !rc ? calloc(secrets.len ? secrets.len : 1, sizeof(*consumed)) : NULL;
    if (!rc && !consumed) rc = fail(error, "out of memory tracking AWS secrets");
    size_t remaining = secrets.len; /* Includes low-entropy matches until a verified secret is consumed. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        const char *id = ids.items[i];
        if (br_ascii_shannon_entropy(br_captures_at(&ids, i)) < 3.0 || list_contains(options.skip_ids, id)) continue;
        char account[14];
        bool has_account = account_from_id(id, account);
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            if (consumed[s] || br_ascii_shannon_entropy(secret) < 4.25) continue;
            br_result result = {0};
            if (make_result(detector, id, secrets.items[s], has_account ? account : NULL, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AWS access key result");
                break;
            }
            const char *skip_reason = NULL;
            if (verify && has_account) {
                if (list_contains(options.denied_accounts, account)) skip_reason = deny_reason;
                else if (options.allowed_accounts && json_object_array_length(options.allowed_accounts) &&
                         !list_contains(options.allowed_accounts, account)) skip_reason = allow_reason;
            }
            if (verify) {
                char *panic_cause = NULL;
                bool sns = has_account && (known_account(account, thinkst_accounts, sizeof(thinkst_accounts) / sizeof(thinkst_accounts[0])) ||
                    known_account(account, knockoff_accounts, sizeof(knockoff_accounts) / sizeof(knockoff_accounts[0])));
                int checked = skip_reason ? br_result_set_verification_error(&result, skip_reason, &secret, 1) :
                    verify_pair(ctx, sns, id, secrets.items[s], remaining > 1, &result, &panic_cause);
                if (checked) {
                    br_result_clear(&result);
                    if (panic_cause && error) { *error = panic_cause; panic_cause = NULL; rc = -1; }
                    else rc = fail(error, "out of memory verifying AWS access key");
                    free(panic_cause);
                    break;
                }
            }
            /* Account-filtered candidates bypass hash rejection, as upstream. */
            if (!skip_reason && !result.verified && hash_like(secrets.items[s])) {
                br_result_clear(&result);
                continue;
            }
            bool verified = result.verified;
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending AWS access key result");
            } else if (verified) {
                consumed[s] = true;
                --remaining;
                break;
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(consumed);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    free(replaced.data);
    return rc;
}

static bool same_id(const br_result *a, const br_result *b)
{
    return !strcmp(a->redacted ? a->redacted : "", b->redacted ? b->redacted : "");
}

static void clean_aws(const br_detector *detector, br_results *results, bool verification_enabled)
{
    (void)detector;
    if (!results || !verification_enabled) return;
    size_t kept = 0;
    for (size_t i = 0; i < results->len; ++i) {
        bool keep = true;
        for (size_t j = 0; keep && j < kept; ++j)
            if (same_id(&results->items[i], &results->items[j])) keep = false;
        for (size_t j = i + 1; keep && j < results->len; ++j)
            if (results->items[j].verified && same_id(&results->items[i], &results->items[j])) keep = false;
        if (!keep) br_result_clear(&results->items[i]);
        else {
            if (kept != i) {
                results->items[kept] = results->items[i];
                memset(&results->items[i], 0, sizeof(results->items[i]));
            }
            ++kept;
        }
    }
    results->len = kept;
}

static aws_patterns patterns;
static const char *const keywords[] = {"AKIA", "ABIA", "ACCA"};
static const br_detector aws = {
    .type = 2, .version = 0, .name = "AWS", .custom_name = "",
    .description = "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. "
                   "API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.",
    .keywords = keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_aws, .clean = clean_aws, .clean_always = true,
};

int br_aws_access_keys_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AWS access key detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile("\\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\\b", &patterns.id, error) != 0) return -1;
    if (!patterns.secret && br_regex_compile("(?:[^A-Za-z0-9+/]|\\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\\z)", &patterns.secret, error) != 0)
        return -1;
    *out = &aws;
    return 0;
}
