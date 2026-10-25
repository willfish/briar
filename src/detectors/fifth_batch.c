/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, airtablepersonalaccesstoken, airvisual,
 * aiven and alchemy detector implementations. */
#include "fifth_batch.h"
#include "detectors.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key; } detector_patterns;
typedef struct { char **items; size_t len, cap; } captures;
typedef struct {
    br_slice input;
    captures *values;
    char *error;
} capture_context;
typedef int (*verifier)(const br_scan_ctx *, const char *, br_result *);

static int fail(char **error, const char *message)
{
    if (error) {
        size_t len = strlen(message) + 1;
        *error = malloc(len);
        if (*error) memcpy(*error, message, len);
    }
    return -1;
}

static void captures_clear(captures *values)
{
    for (size_t i = 0; i < values->len; ++i) free(values->items[i]);
    free(values->items);
    memset(values, 0, sizeof(*values));
}

static int collect_unique_capture(void *user, const br_span *groups, size_t ngroups)
{
    capture_context *context = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > context->input.len)
        return fail(&context->error, "invalid detector capture");
    const unsigned char *data = context->input.data + groups[1].begin;
    size_t len = groups[1].end - groups[1].begin;
    captures *values = context->values;
    for (size_t i = 0; i < values->len; ++i)
        if (strlen(values->items[i]) == len && !memcmp(values->items[i], data, len)) return 0;
    if (values->len == values->cap) {
        size_t cap = values->cap ? values->cap * 2 : 8;
        if (cap < values->cap || cap > SIZE_MAX / sizeof(*values->items))
            return fail(&context->error, "too many detector captures");
        void *items = realloc(values->items, cap * sizeof(*values->items));
        if (!items) return fail(&context->error, "out of memory collecting detector captures");
        values->items = items;
        values->cap = cap;
    }
    char *copy = malloc(len + 1);
    if (!copy) return fail(&context->error, "out of memory copying detector capture");
    memcpy(copy, data, len);
    copy[len] = '\0';
    values->items[values->len++] = copy;
    return 0;
}

static int find_unique(const br_regex *regex, br_slice input, captures *values, char **error)
{
    capture_context context = {input, values, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(regex, input, collect_unique_capture, &context, &regex_error);
    if (context.error) {
        free(regex_error);
        regex_error = context.error;
    }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static int key_error(br_result *result, const char *cause)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int verify_redacted(const br_scan_ctx *ctx, const br_http_request *request,
                            br_result *result)
{
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, request, &response, &error) != 0) {
        rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        /* Both upstream callers return nil ExtraData and ignore body-drain errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: {
            char message[80];
            snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
            rc = key_error(result, message);
            break;
        }
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int verify_unredacted(const br_scan_ctx *ctx, const br_http_request *request,
                              br_result *result)
{
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    /* AirVisual and Aiven omit secrets in SetVerificationError upstream. */
    if (br_http_send(ctx, request, &response, &error) != 0) {
        rc = br_result_set_verification_error(result, error ? error : "HTTP transport failed", NULL, 0);
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default: {
            char message[80];
            snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            rc = br_result_set_verification_error(result, message, NULL, 0);
            break;
        }
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int verify_airtable_pat(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    char auth[90];
    snprintf(auth, sizeof(auth), "Bearer %s", token);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.airtable.com/v0/meta/whoami",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 1015,
    };
    return verify_redacted(ctx, &request, result);
}

static int verify_airvisual(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128], auth[44];
    snprintf(url, sizeof(url), "https://api.airvisual.com/v2/countries?key=%s", key);
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.airvisual+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 498,
    };
    return verify_unredacted(ctx, &request, result);
}

static int verify_aiven(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[381];
    snprintf(auth, sizeof(auth), "aivenv1 %s", key);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.aiven.io/v1/project",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 917,
    };
    return verify_unredacted(ctx, &request, result);
}

static int emit_result(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const char *key, const char *part_name, verifier check,
                        br_results *out, char **error)
{
    size_t len = strlen(key);
    br_result result = {.detector_type = detector->type};
    result.raw.data = malloc(len);
    result.secret_parts = json_object_new_object();
    br_json *value = json_object_new_string(key);
    if (!result.raw.data || !result.secret_parts || !value) {
        if (value) json_object_put(value);
        goto memory_error;
    }
    memcpy(result.raw.data, key, len);
    result.raw.len = len;
    if (json_object_object_add(result.secret_parts, part_name, value) != 0) {
        json_object_put(value);
        goto memory_error;
    }
    if (verify && check(ctx, key, &result) != 0) goto memory_error;
    if (br_results_push(out, &result) != 0) goto memory_error;
    return 0;
memory_error:
    br_result_clear(&result);
    return fail(error, "out of memory creating detector result");
}

static int scan_unique_keys(const br_detector *detector, const br_scan_ctx *ctx,
                             bool verify, br_slice input, br_results *out, char **error,
                             const char *part_name, verifier check)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid detector scan arguments");
    const detector_patterns *patterns = detector->state;
    if (!patterns->key) return fail(error, "uninitialized fifth-batch detector");
    captures keys = {0};
    int rc = find_unique(patterns->key, input, &keys, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i)
        rc = emit_result(detector, ctx, verify, keys.items[i], part_name, check, out, error);
    captures_clear(&keys);
    return rc;
}

static int scan_airtable_pat(const br_detector *detector, const br_scan_ctx *ctx,
                              bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "token", verify_airtable_pat);
}

static int scan_airvisual(const br_detector *detector, const br_scan_ctx *ctx,
                           bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "key", verify_airvisual);
}

static int scan_aiven(const br_detector *detector, const br_scan_ctx *ctx,
                       bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "key", verify_aiven);
}

static detector_patterns airtable_pat_patterns, airvisual_patterns, aiven_patterns;
static const char *const airtable_keywords[] = {"airtable"};
static const char *const airvisual_keywords[] = {"airvisual"};
static const char *const aiven_keywords[] = {"aiven"};

static const br_detector airtable_pat = {
    .type = 1015, .version = 0, .name = "AirtablePersonalAccessToken", .custom_name = "",
    .description = "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases.",
    .keywords = airtable_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &airtable_pat_patterns, .scan = scan_airtable_pat,
};
static const br_detector airvisual = {
    .type = 498, .version = 0, .name = "AirVisual", .custom_name = "",
    .description = "AirVisual provides air quality information and monitoring. The API key allows access to various air quality data and services.",
    .keywords = airvisual_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &airvisual_patterns, .scan = scan_airvisual,
};
static const br_detector aiven = {
    .type = 917, .version = 0, .name = "Aiven", .custom_name = "",
    .description = "Aiven is a managed cloud service that provides various open-source data infrastructure services. Aiven API keys can be used to access and manage these services.",
    .keywords = aiven_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &aiven_patterns, .scan = scan_aiven,
};
static const br_detector *implemented[] = {&airtable_pat, &airvisual, &aiven, NULL};

static int compile_prefixed(const br_detector *detector, const char *capture,
                             br_regex **out, char **error)
{
    if (*out) return 0;
    char *prefix = NULL;
    if (br_prefix_regex(detector->keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate detector prefix pattern");
    size_t len = strlen(prefix) + strlen(capture) + 1;
    char *pattern = malloc(len);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate detector pattern");
    }
    snprintf(pattern, len, "%s%s", prefix, capture);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

int br_fifth_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid fifth-batch outputs");
    if (br_alchemy_init(&implemented[3], error) != 0 ||
        compile_prefixed(&airtable_pat, "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b", &airtable_pat_patterns.key, error) != 0 ||
        compile_prefixed(&airvisual, "\\b([a-z0-9-]{36})\\b", &airvisual_patterns.key, error) != 0 ||
        compile_prefixed(&aiven, "([a-zA-Z0-9/+=]{372})", &aiven_patterns.key, error) != 0)
        return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_fifth_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == 1015 || detector->type == 498 || detector->type == 917 || detector->type == 907;
}
