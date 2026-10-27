/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudinary/cloudinary.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *cloud, *key, *secret; } cloudinary_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int put_part(br_result *result, const char *name, br_slice value)
{
    /* Only bounded captured cloud names (<=50) and secrets (27) reach here. */
    br_json *text = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!text) return -1;
    if (json_object_object_add(result->secret_parts, name, text)) { json_object_put(text); return -1; }
    return 0;
}

static int finding(br_result *result, int32_t type, br_slice cloud, br_slice key, br_slice secret)
{
    if (br_finding_key_bytes(result, type, key, "api_key")) return -1;
    /* A single exact-size composite allocation: Raw is APIKEY, while RawV2
     * is CLOUD:APIKEY:APISECRET. All three lengths are regex-bounded. */
    size_t len = cloud.len + key.len + secret.len + 2;
    result->raw_v2.data = malloc(len);
    if (!result->raw_v2.data) return -1;
    size_t at = 0;
    memcpy(result->raw_v2.data + at, cloud.data, cloud.len); at += cloud.len; result->raw_v2.data[at++] = ':';
    memcpy(result->raw_v2.data + at, key.data, key.len); at += key.len; result->raw_v2.data[at++] = ':';
    memcpy(result->raw_v2.data + at, secret.data, secret.len);
    result->raw_v2.len = len;
    return put_part(result, "cloud_name", cloud) || put_part(result, "api_secret", secret) ? -1 : 0;
}

static int set_cause(br_result *result, const char *cause, br_slice cloud, br_slice key, br_slice secret)
{
    /* Order is observable for overlapping values: CLOUD, then KEY, then SECRET.
     * Setter +1 is a fatal resource result, never a candidate outcome. */
    const br_slice secrets[] = {cloud, key, secret};
    return br_result_set_verification_error(result, cause, secrets, 3) ? -1 : 0;
}

static int verify_cloudinary(const br_scan_ctx *ctx, br_slice cloud, br_slice key, br_slice secret,
                              br_result *result)
{
    /* NewRequestWithContext fails BEFORE SetBasicAuth. Retain the cause. */
    if (!ctx) return set_cause(result, "net/http: nil Context", cloud, key, secret);
    /* url.URL{https, api.cloudinary.com, path.Join("v1_1", cloud, "usage")}
     * has this exact String() for the captured ASCII-letter/alnum/hyphen
     * grammar: no slash, dot segment, escaping or case normalization is added. */
    char url[sizeof("https://api.cloudinary.com/v1_1/") + 50 + sizeof("/usage") - 1];
    snprintf(url, sizeof(url), "https://api.cloudinary.com/v1_1/%s/usage", (const char *)cloud.data);
    char *authorization = NULL;
    if (br_http_basic_auth(key, secret, &authorization, NULL)) { free(authorization); return -1; }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error ? transport_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Copy/redact before releasing any cause owner. Source ignores deferred
     * drain/close errors; eager ABI1 buffering/release and http.NoBody/client
     * configuration/native diagnostics remain explicit parity gaps. */
    int rc = set_cause(result, cause, cloud, key, secret);
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return rc ? -1 : 0;
}

static int scan_cloudinary(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Cloudinary scan");
    const cloudinary_patterns *compiled = detector->state;
    if (!compiled->cloud || !compiled->key || !compiled->secret) return fail(error, "uninitialized Cloudinary patterns");
    br_captures clouds = {0}, keys = {0}, secrets = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->cloud, input, &clouds, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, true, &owned_error);
    /* Independent byte-unique maps, deterministic first-seen traversal. No
     * equality filter, consumption, cache or successful-verification break. */
    for (size_t c = 0; !rc && c < clouds.len; ++c) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            for (size_t s = 0; !rc && s < secrets.len; ++s) {
                br_result result = {0};
                br_slice cloud = br_captures_at(&clouds, c), key = br_captures_at(&keys, k), secret = br_captures_at(&secrets, s);
                if (finding(&result, detector->type, cloud, key, secret)) rc = fail(&owned_error, "cannot create Cloudinary result");
                if (!rc && verify && verify_cloudinary(ctx, cloud, key, secret, &result)) rc = fail(&owned_error, "cannot verify Cloudinary candidate");
                if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Cloudinary result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&clouds); br_captures_clear(&keys); br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static cloudinary_patterns patterns;
static const char *const keywords[] = {"cloudinary"};
static const br_detector cloudinary = {
    .type = 1048, .version = 0, .name = "Cloudinary", .custom_name = "",
    .description = "Cloudinary is a cloud-based media management platform. Cloudinary API keys can be used to upload, manage, and deliver media assets.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_cloudinary,
};

int br_cloudinary_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Cloudinary detector output");
    *out = NULL;
    if (!patterns.cloud && br_regex_compile("(?i:cloudinary)(?:.|[\\n\\r]){0,47}?(?i:name|@)(?:.){0,10}?\\b([a-zA-Z][a-zA-Z0-9-]{2,49})\\b", &patterns.cloud, error)) return -1;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b(\\d{15})\\b", &patterns.key, error)) return -1;
    if (!patterns.secret && br_regex_compile_prefixed(keywords, 1, "\\b([A-Za-z0-9_-]{27})\\b", &patterns.secret, error)) return -1;
    *out = &cloudinary;
    return 0;
}
