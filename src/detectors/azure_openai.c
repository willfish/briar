/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azure_openai/azure_openai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } openai_patterns;
static br_host_cache invalid_services = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { bool object_nonempty; char *cause; } deployments_fields;

static int type_error(deployments_fields *fields, br_json *value, const char *field, const char *expected)
{
    return br_json_type_cause(value, field, expected, &fields->cause) == 0 ? 1 : -1;
}

static int read_deployment_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (br_json_field_name(name, "id") && value && !json_object_is_type(value, json_type_string))
        return type_error(user, value, "deployment.data.id", "string");
    return 0;
}

static int read_deployment(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    if (!value) return 0; /* Null into a deployment struct is a no-op. */
    if (!json_object_is_type(value, json_type_object))
        return type_error(user, value, "deploymentsResponse.data", "azure_openai.deployment");
    return br_json_each_member(encoded, read_deployment_field, user);
}

static int read_response_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    deployments_fields *fields = user;
    if (br_json_field_name(name, "data")) {
        if (!value) return 0;
        if (!json_object_is_type(value, json_type_array))
            return type_error(fields, value, "deploymentsResponse.data", "[]azure_openai.deployment");
        /* IDs do not affect validity, but EVERY known field must type-check.
         * Ordered visits retain errors hidden by later duplicate members. */
        return br_json_each_element(encoded, read_deployment, fields);
    }
    if (br_json_field_name(name, "object") && value) {
        if (!json_object_is_type(value, json_type_string))
            return type_error(fields, value, "deploymentsResponse.object", "string");
        fields->object_nonempty = br_json_text(value).len != 0;
    }
    return 0; /* Unknown values are ignored, not decoded through map float64. */
}

static int decode_response(br_slice body, bool *verified, char **cause)
{
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc) {
        json_object_put(root);
        if (rc < 0) return -1;
        free(*cause);
        *cause = NULL; /* Source suppresses errors for syntactically invalid JSON. */
        return 0;
    }
    deployments_fields fields = {0};
    if (root) {
        rc = json_object_is_type(root, json_type_object) ? br_json_each_member(body, read_response_field, &fields) :
            type_error(&fields, root, NULL, "azure_openai.deploymentsResponse");
    }
    json_object_put(root);
    if (rc < 0) { free(fields.cause); return -1; }
    /* The source wraps typed errors with %w; SetVerificationError unwraps that
     * message to its LAST cause, so only the typed JSON cause is retained. */
    *cause = fields.cause;
    *verified = !rc && fields.object_nonempty;
    return 0;
}

static int unexpected_status(int status, const char *url, char **cause)
{
    const char prefix[] = "unexpected response status ", middle[] = " for ";
    char code[32];
    int n = snprintf(code, sizeof(code), "%d", status);
    if (n < 0 || (size_t)n >= sizeof(code)) return -1;
    size_t url_len = strlen(url), fixed = sizeof(prefix) - 1 + (size_t)n + sizeof(middle);
    if (url_len > SIZE_MAX - fixed) return -1;
    *cause = malloc(fixed + url_len);
    if (!*cause) return -1;
    size_t at = sizeof(prefix) - 1;
    memcpy(*cause, prefix, at);
    memcpy(*cause + at, code, (size_t)n); at += (size_t)n;
    memcpy(*cause + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(*cause + at, url, url_len + 1);
    return 0;
}

static int verify_openai(const br_scan_ctx *ctx, const char *host, const char *key,
                         bool *verified, char **cause)
{
    *verified = false;
    *cause = NULL;
    const char prefix[] = "https://", suffix[] = "/openai/deployments?api-version=2023-03-15-preview";
    size_t host_len = strlen(host), fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (host_len > SIZE_MAX - fixed) return -1;
    char *url = malloc(host_len + fixed);
    if (!url) return -1;
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, host, host_len);
    memcpy(url + sizeof(prefix) - 1 + host_len, suffix, sizeof(suffix));
    const br_header headers[] = {{"Api-Key", key}, {"Content-Type", "application/json"}};
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 1007};
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        *cause = error;
        error = NULL;
        if (!*cause && !(*cause = strdup("HTTP transport failed"))) rc = -1;
    } else if (response.status == 200) {
        if (response.body_error) {
            if (!(*cause = strdup(response.body_error))) rc = -1;
        } else rc = decode_response(response.body, verified, cause);
    } else if (response.status != 401) rc = unexpected_status(response.status, url, cause);
    br_http_release(ctx, &response);
    free(error);
    free(url);
    return rc;
}

static int make_result(const br_detector *detector, const char *token, br_result *result)
{
    if (br_finding_key(result, detector->type, token, "key") != 0) return -1;
    result->redacted = malloc(14);
    if (!result->redacted) return -1;
    memcpy(result->redacted, token, 3);
    memcpy(result->redacted + 3, "...", 3);
    memcpy(result->redacted + 6, token + 25, 8); /* Seven final bytes plus NUL. */
    return 0;
}

static int select_host(br_result *result, const char *token, const char *host, bool verified, const char *cause)
{
    size_t host_len = strlen(host);
    if (host_len > SIZE_MAX - 33) return -1;
    result->raw_v2.data = malloc(host_len + 33);
    if (!result->raw_v2.data) return -1;
    result->raw_v2.len = host_len + 33;
    memcpy(result->raw_v2.data, token, 32);
    result->raw_v2.data[32] = ':';
    memcpy(result->raw_v2.data + 33, host, host_len);
    result->verified = verified;
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int scan_openai(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureOpenAI scan arguments");
    const openai_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->host) return fail(error, "uninitialized AzureOpenAI patterns");
    br_captures keys = {0}, matches = {0}, hosts = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc && keys.len) rc = br_captures_find(compiled->host, input, &matches, false, error);
    for (size_t i = 0; !rc && i < matches.len; ++i) {
        bool cached = false;
        if (br_host_cache_contains(&invalid_services, matches.items[i], &cached) != 0)
            rc = fail(error, "wall clock unavailable");
        else if (!cached) rc = br_captures_push(&hosts, br_captures_at(&matches, i), true, error);
    }
    bool *removed = !rc && hosts.len ? calloc(hosts.len, sizeof(*removed)) : NULL;
    if (!rc && hosts.len && !removed) rc = fail(error, "out of memory tracking Azure OpenAI hosts");
    size_t remaining = hosts.len;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        const char *token = keys.items[k];
        br_result result = {0};
        if (make_result(detector, token, &result) != 0) rc = fail(error, "cannot create AzureOpenAI result");
        for (size_t h = 0; !rc && h < hosts.len; ++h) {
            if (!verify || removed[h]) continue;
            bool verified = false;
            char *cause = NULL;
            if (verify_openai(ctx, hosts.items[h], token, &verified, &cause) != 0)
                rc = fail(error, "cannot verify AzureOpenAI candidate");
            else if (verified || remaining == 1) {
                /* This branch MUST precede DNS classification: the final host's
                 * DNS error is retained in the finding, and is NOT cached. */
                if (select_host(&result, token, hosts.items[h], verified, cause) != 0)
                    rc = fail(error, "cannot select AzureOpenAI host");
                free(cause);
                break;
            } else if (cause && strstr(cause, "no such host")) {
                removed[h] = true;
                --remaining;
                if (br_host_cache_add(&invalid_services, hosts.items[h]) != 0)
                    rc = fail(error, "cannot cache invalid AzureOpenAI service");
            }
            free(cause);
        }
        if (!rc && br_results_push(out, &result) != 0) rc = fail(error, "out of memory appending AzureOpenAI result");
        br_result_clear(&result);
    }
    free(removed);
    br_captures_clear(&hosts);
    br_captures_clear(&matches);
    br_captures_clear(&keys);
    return rc;
}

static openai_patterns patterns;
static const char *const keywords[] = {".openai.azure.com"};
static const char *const key_prefixes[] = {"api[_.-]?key", "openai[_.-]?key"};
static const br_detector openai = {
    .type = 1007, .version = 0, .name = "AzureOpenAI", .custom_name = "",
    .description = "Azure OpenAI provides various AI models and services. The API keys can be used to access and interact with these models and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_openai,
};

int br_azure_openai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureOpenAI detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(key_prefixes, 2, "\\b(?-i:([a-f0-9]{32}))\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.host && br_regex_compile("(?i)([a-z0-9-]+\\.openai\\.azure\\.com)", &patterns.host, error) != 0)
        return -1;
    *out = &openai;
    return 0;
}
