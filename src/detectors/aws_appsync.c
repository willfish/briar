/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aws/appsync/appsync.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *endpoint; } appsync_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_appsync(const br_scan_ctx *ctx, const char *endpoint,
                          const char *key, br_result *result)
{
    static const unsigned char query[] = "{\"query\":\"query { __typename }\"}";
    const br_header headers[] = {{"Content-Type", "application/json"}, {"x-api-key", key}};
    const br_http_request request = {
        .method = "POST", .url = endpoint, .headers = headers, .nheaders = 2,
        .body = {query, sizeof(query) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 1052,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break; /* Status only; drain errors are ignored. */
        case 502:
            if (response.body_error) cause = response.body_error;
            else if (br_slice_find(response.body,
                    (br_slice){(const unsigned char *)"No schema definition exists", sizeof("No schema definition exists") - 1}, 0) != SIZE_MAX)
                result->verified = true;
            else cause = "502 Bad Gateway: unexpected response";
            break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int make_result(br_result *result, int32_t type, br_slice key, br_slice endpoint)
{
    if (br_finding_pair_bytes(result, type, key, "key", endpoint, "endpoint",
                              (br_slice){(const unsigned char *)":", 1}) != 0)
        return -1;
    /* Raw remains key, but source RawV2 is endpoint:key, not the shared key:endpoint. */
    memcpy(result->raw_v2.data, endpoint.data, endpoint.len);
    result->raw_v2.data[endpoint.len] = ':';
    memcpy(result->raw_v2.data + endpoint.len + 1, key.data, key.len);
    result->extra_data = json_object_new_object();
    br_json *base = json_object_new_string((const char *)endpoint.data);
    if (!result->extra_data || !base) { json_object_put(base); return -1; }
    if (json_object_object_add(result->extra_data, "base_url", base) == 0) return 0;
    json_object_put(base);
    return -1;
}

static int scan_appsync(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AWSAppSync scan arguments");
    const appsync_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->endpoint) return fail(error, "uninitialized AWSAppSync patterns");
    br_captures keys = {0}, bases = {0}, endpoints = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->endpoint, input, &bases, false, error);
    const char suffix[] = "/graphql";
    for (size_t i = 0; !rc && i < bases.len; ++i) {
        br_slice base = br_captures_at(&bases, i);
        if (base.len > SIZE_MAX - sizeof(suffix)) {
            rc = fail(error, "AWSAppSync endpoint too large");
            break;
        }
        char *endpoint = malloc(base.len + sizeof(suffix));
        if (!endpoint) { rc = fail(error, "out of memory normalizing AWSAppSync endpoint"); break; }
        memcpy(endpoint, base.data, base.len);
        memcpy(endpoint + base.len, suffix, sizeof(suffix));
        rc = br_captures_push(&endpoints,
            (br_slice){(const unsigned char *)endpoint, base.len + sizeof(suffix) - 1}, true, error);
        free(endpoint);
    }
    /* Go map order is unspecified; retain each distinct key/normalized endpoint pair. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t e = 0; !rc && e < endpoints.len; ++e) {
            br_result result = {0};
            if (make_result(&result, detector->type, br_captures_at(&keys, k), br_captures_at(&endpoints, e)) != 0 ||
                (verify && verify_appsync(ctx, endpoints.items[e], keys.items[k], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AWSAppSync result");
            }
        }
    }
    br_captures_clear(&endpoints);
    br_captures_clear(&bases);
    br_captures_clear(&keys);
    return rc;
}

static appsync_patterns patterns;
static const char *const keywords[] = {"da2-"};
static const br_detector appsync = {
    .type = 1052, .version = 0, .name = "AWSAppSync", .custom_name = "",
    .description = "AWS AppSync is a managed GraphQL service. This detector identifies exposed AppSync API keys.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_appsync,
};

int br_aws_appsync_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AWSAppSync detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile("\\b(da2-[a-z0-9]{26})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.endpoint && br_regex_compile(
            "(https:\\/\\/[a-z0-9]{26}\\.appsync-api\\.[a-z0-9-]+\\.amazonaws\\.com)([^a-zA-Z0-9.-]|$)",
            &patterns.endpoint, error) != 0)
        return -1;
    *out = &appsync;
    return 0;
}
