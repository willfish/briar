/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipquality/ipquality.go. */
#include "detectors.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char credits_needle[] = "insufficient credits";
static const char credits_cause[] = "couldn't verify; API Key has insufficient credits";

typedef struct {
    bool success;
    br_json *message;
    char *cause;
} ipquality_fields;

static bool contains_span(br_slice text, const char *needle)
{
    size_t n = strlen(needle);
    if (n > text.len) return false;
    for (size_t i = 0; i + n <= text.len; ++i)
        if (!memcmp(text.data + i, needle, n)) return true;
    return false;
}

/* Null is a no-op. A wrong type records the earliest cause and still visits
 * later members, so a later allocation failure is not hidden as a type error. */
static int ipquality_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    ipquality_fields *fields = user;
    bool success = br_json_field_name(name, "success");
    bool message = br_json_field_name(name, "message");
    if ((!success && !message) || !value || json_object_is_type(value, json_type_null)) return 0;
    if (success) {
        if (json_object_is_type(value, json_type_boolean)) fields->success = json_object_get_boolean(value);
        else if (!fields->cause &&
                 br_json_type_cause(value, "apiResponse.success", "bool", &fields->cause) != 0)
            return -1;
        return 0;
    }
    if (json_object_is_type(value, json_type_string)) {
        br_json *kept = json_object_get(value);
        if (!kept) return -1;
        json_object_put(fields->message);
        fields->message = kept;
        return 0;
    }
    if (!fields->cause && br_json_type_cause(value, "apiResponse.message", "string", &fields->cause) != 0)
        return -1;
    return 0;
}

/* 0 decoded, 1 owns *cause, -1 resource failure. Whole document, not a
 * float64 map or first-document decode. Root null is a zero value. */
static int ipquality_decode(br_slice body, bool *success, br_json **message, char **cause)
{
    *success = false;
    *message = NULL;
    *cause = NULL;
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    /* json-c represents JSON null as a NULL object. That is a zero value, not a resource failure. */
    if (rc || !root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        return rc;
    }
    if (!json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, "ipquality.apiResponse", cause) == 0 ? 1 : -1;
        json_object_put(root);
        return rc;
    }
    ipquality_fields fields = {0};
    rc = br_json_each_member(body, ipquality_member, &fields);
    json_object_put(root);
    /* The callback returns 0 or a resource failure. The helper also propagates
     * a positive owned callback return, and every nonzero visit is fatal. */
    if (rc != 0) {
        json_object_put(fields.message);
        free(fields.cause);
        return -1;
    }
    if (fields.cause) {
        json_object_put(fields.message);
        *cause = fields.cause;
        return 1;
    }
    *success = fields.success;
    *message = fields.message;
    return 0;
}

static int set_cause(br_result *result, const char *cause)
{
    /* Source passes no secret arguments, so an injected cause keeps the key. */
    return br_result_set_verification_error(result, cause, NULL, 0) == 0 ? 0 : -1;
}

static int verify_ipquality(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const char base[] = "https://www.ipqualityscore.com/api/json/account/";
    char url[sizeof(base) + 32];
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key, 32);
    url[sizeof(base) + 31] = '\0';
    /* NewRequestWithContext fails before URL parse. This is not a send. */
    if (!ctx) return set_cause(result, "net/http: nil Context");

    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 0, .detector_type = 478,
    };
    br_http_response response = {0};
    char *send_error = NULL, *decode_cause = NULL, *owned_body_error = NULL;
    char status_error[48];
    br_json *message = NULL;
    const char *cause = NULL;
    bool verified = false;
    int fatal = 0;

    /* Locals only. Upstream returns after deferred drain and Close, and the
     * caller then assigns Verified and calls SetVerificationError. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* A missing send cause is ordinary, not an owned failure. Do not invent one. */
        cause = send_error;
    } else if (response.status != 200) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) fatal = 1;
        else cause = status_error;
    } else if (response.body_error) {
        owned_body_error = strdup(response.body_error);
        if (!owned_body_error) fatal = 1;
        else cause = owned_body_error;
    } else {
        bool success = false;
        int decoded = ipquality_decode(response.body, &success, &message, &decode_cause);
        if (decoded < 0) fatal = 1;
        else if (decoded > 0) cause = decode_cause;
        else if (success) verified = true;
        else if (contains_span(br_json_text(message), credits_needle)) cause = credits_cause;
        /* Invalid-key and every other false message, including empty, stay nil. */
    }
    if (fatal) {
        br_http_release(ctx, &response);
        json_object_put(message);
        free(send_error);
        free(decode_cause);
        free(owned_body_error);
        return -1; /* No setter and no publication. */
    }
    /* Send, decode, status, and static causes already survive release. */
    br_http_release(ctx, &response);
    result->verified = verified;
    fatal = set_cause(result, cause); /* Mandatory, including a NULL cause. */
    json_object_put(message);
    free(send_error);
    free(decode_cause);
    free(owned_body_error);
    return fatal ? -1 : 0;
}

static int scan_ipquality(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_ipquality, error);
}

static const char *const keywords[] = {"ipquality"};
static br_detector ipquality = {
    .type = 478, .version = 0, .name = "IPQuality", .custom_name = "",
    .description = "IPQualityScore provides tools to detect and prevent fraudulent activity. "
                   "IPQualityScore API keys can be used to access their fraud prevention services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_ipquality,
};

int br_ipquality_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid IPQuality detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&ipquality, "\\b([0-9a-zA-Z]{32})\\b", error) != 0) return -1;
    *out = &ipquality;
    return 0;
}
