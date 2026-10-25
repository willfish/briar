/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, airbrakeprojectkey, airbrakeuserkey,
 * airship and airtableoauth detector implementations. */
#include "fourth_batch.h"
#include "detectors.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } detector_patterns;
typedef struct { char **items; size_t len, cap; } captures;
typedef struct {
    br_slice input;
    captures *values;
    char *error;
} capture_context;
typedef int (*verifier)(const br_scan_ctx *, const char *, const char *, br_result *);

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

static int verify_status_only(const br_scan_ctx *ctx, const br_http_request *request,
                               br_result *result)
{
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    /* All three upstream callers omit secrets from SetVerificationError. */
    if (br_http_send(ctx, request, &response, &error) != 0) {
        rc = br_result_set_verification_error(result, error ? error : "HTTP transport failed", NULL, 0);
    } else {
        /* Their deferred body drains ignore errors, so only status matters. */
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

static int verify_airbrake_user(const br_scan_ctx *ctx, const char *key,
                                 const char *id, br_result *result)
{
    (void)id;
    char url[160];
    snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects?key=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 126,
    };
    return verify_status_only(ctx, &request, result);
}

static int verify_airship(const br_scan_ctx *ctx, const char *key,
                           const char *id, br_result *result)
{
    (void)id;
    char auth[99];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.urbanairship+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://go.urbanairship.com/api/schedules",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 277,
    };
    return verify_status_only(ctx, &request, result);
}

static int verify_airtable_oauth(const br_scan_ctx *ctx, const char *token,
                                  const char *id, br_result *result)
{
    (void)id;
    size_t token_len = strlen(token);
    if (token_len > SIZE_MAX - sizeof("Bearer ")) return -1;
    size_t len = token_len + sizeof("Bearer ");
    char *auth = malloc(len);
    if (!auth) return -1;
    snprintf(auth, len, "Bearer %s", token);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.airtable.com/v0/meta/whoami",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 1014,
    };
    br_http_response response = {0};
    char *error = NULL;
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = br_result_set_verification_error(result, error ? error : "HTTP transport failed", &secret, 1);
    } else {
        /* verifyMatch returns nil ExtraData on every branch and ignores body errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: {
            char message[80];
            snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
            rc = br_result_set_verification_error(result, message, &secret, 1);
            break;
        }
        }
    }
    br_http_release(ctx, &response);
    free(error);
    free(auth);
    return rc;
}

static int add_string(br_json *object, const char *name, const char *value)
{
    br_json *string = json_object_new_string(value);
    if (!string) return -1;
    if (json_object_object_add(object, name, string) != 0) {
        json_object_put(string);
        return -1;
    }
    return 0;
}

static int emit_result(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const char *key, const char *id, const char *part_name,
                        verifier check, br_results *out, char **error)
{
    size_t key_len = strlen(key), id_len = id ? strlen(id) : 0;
    br_result result = {.detector_type = detector->type};
    result.raw.data = malloc(key_len);
    result.secret_parts = json_object_new_object();
    if (!result.raw.data || !result.secret_parts) goto memory_error;
    memcpy(result.raw.data, key, key_len);
    result.raw.len = key_len;
    if (add_string(result.secret_parts, part_name, key) != 0) goto memory_error;
    if (id) {
        if (id_len > SIZE_MAX - key_len) goto memory_error;
        result.raw_v2.data = malloc(key_len + id_len);
        if (!result.raw_v2.data) goto memory_error;
        memcpy(result.raw_v2.data, key, key_len);
        memcpy(result.raw_v2.data + key_len, id, id_len);
        result.raw_v2.len = key_len + id_len;
        if (add_string(result.secret_parts, "id", id) != 0) goto memory_error;
    }
    if (detector->type == 125 || detector->type == 126) {
        result.extra_data = json_object_new_object();
        if (!result.extra_data || add_string(result.extra_data, "rotation_guide",
                "https://howtorotate.com/docs/tutorials/airbrake/") != 0) goto memory_error;
    }
    if (verify && check(ctx, key, id, &result) != 0) goto memory_error;
    if (br_results_push(out, &result) != 0) goto memory_error;
    return 0;
memory_error:
    br_result_clear(&result);
    return fail(error, "out of memory creating detector result");
}

static int valid_scan(const br_detector *detector, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid detector scan arguments");
    const detector_patterns *patterns = detector->state;
    if (!patterns->key) return fail(error, "uninitialized fourth-batch detector");
    return 0;
}

static int scan_unique_keys(const br_detector *detector, const br_scan_ctx *ctx,
                             bool verify, br_slice input, br_results *out, char **error,
                             const char *part_name, verifier check)
{
    if (valid_scan(detector, input, out, error) != 0) return -1;
    const detector_patterns *patterns = detector->state;
    captures keys = {0};
    int rc = find_unique(patterns->key, input, &keys, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i)
        rc = emit_result(detector, ctx, verify, keys.items[i], NULL, part_name, check, out, error);
    captures_clear(&keys);
    return rc;
}

static int scan_airbrake_user(const br_detector *detector, const br_scan_ctx *ctx,
                              bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "key", verify_airbrake_user);
}

static int scan_airship(const br_detector *detector, const br_scan_ctx *ctx,
                         bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "key", verify_airship);
}

static int scan_airtable_oauth(const br_detector *detector, const br_scan_ctx *ctx,
                                bool verify, br_slice input, br_results *out, char **error)
{
    return scan_unique_keys(detector, ctx, verify, input, out, error, "token", verify_airtable_oauth);
}

static detector_patterns airbrake_user_patterns;
static detector_patterns airship_patterns, airtable_oauth_patterns;
static const char *const airbrake_keywords[] = {"airbrake"};
static const char *const airship_keywords[] = {"airship"};
static const char *const airtable_keywords[] = {"airtable"};

static const br_detector airbrake_user = {
    .type = 126, .version = 0, .name = "AirbrakeUserKey", .custom_name = "",
    .description = "Airbrake is an error and performance monitoring service. Airbrake User Keys can be used to access and manage error reports and performance data.",
    .keywords = airbrake_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &airbrake_user_patterns, .scan = scan_airbrake_user,
};
static const br_detector airship = {
    .type = 277, .version = 0, .name = "Airship", .custom_name = "",
    .description = "Airship is a customer engagement platform that provides tools for mobile app messaging, in-app messaging, and web notifications. Airship API keys can be used to access and manage these messaging services.",
    .keywords = airship_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &airship_patterns, .scan = scan_airship,
};
static const br_detector airtable_oauth = {
    .type = 1014, .version = 0, .name = "AirtableOAuth", .custom_name = "",
    .description = "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases.",
    .keywords = airtable_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &airtable_oauth_patterns, .scan = scan_airtable_oauth,
};
static const br_detector *implemented[] = {
    NULL, &airbrake_user, &airship, &airtable_oauth,
};

static int compile_prefixed(const br_detector *detector, const char *capture,
                             br_regex **out, char **error)
{
    if (*out) return 0;
    char *prefix = NULL;
    if (br_prefix_regex(detector->keywords, detector->nkeywords, &prefix) != 0)
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

int br_fourth_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid fourth-batch outputs");
    if (br_airbrakeprojectkey_init(&implemented[0], error) != 0 ||
        compile_prefixed(&airbrake_user, "\\b([a-zA-Z-0-9]{40})\\b", &airbrake_user_patterns.key, error) != 0 ||
        compile_prefixed(&airship, "\\b([0-9a-zA-Z]{91})\\b", &airship_patterns.key, error) != 0)
        return -1;
    if (!airtable_oauth_patterns.key &&
        br_regex_compile("\\b([[:alnum:]]+\\.v1\\.[a-zA-Z0-9_-]+\\.[a-f0-9]+)\\b",
                         &airtable_oauth_patterns.key, error) != 0) return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_fourth_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == 125 || detector->type == 126 || detector->type == 277 || detector->type == 1014;
}
