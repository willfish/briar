/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, accuweather/{v1,v2}, adafruitio and adobeio. */
#include "second_batch.h"
#include "detectors.h"

#include <json-c/json.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } detector_patterns;
typedef struct { char **items; size_t len, cap; } captures;
typedef struct {
    br_slice input;
    captures *values;
    bool unique, entropy_filter;
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

static bool sufficient_key_entropy(const unsigned char *key, size_t len)
{
    /* Accuweather captures are ASCII, so rune counts equal byte counts here. */
    double counts[128] = {0};
    for (size_t i = 0; i < len; ++i) ++counts[key[i]];
    double inverse_total = 1.0 / (double)len, entropy = 0;
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        if (!counts[i]) continue;
        double probability = counts[i] * inverse_total;
        entropy += probability * log2(probability);
    }
    return -entropy >= 4.0;
}

static int collect_capture(void *user, const br_span *groups, size_t ngroups)
{
    capture_context *context = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > context->input.len)
        return fail(&context->error, "invalid detector capture");
    const unsigned char *key = context->input.data + groups[1].begin;
    size_t len = groups[1].end - groups[1].begin;
    if (context->entropy_filter && !sufficient_key_entropy(key, len)) return 0;
    captures *values = context->values;
    if (context->unique) {
        for (size_t i = 0; i < values->len; ++i)
            if (strlen(values->items[i]) == len && !memcmp(values->items[i], key, len)) return 0;
    }
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
    memcpy(copy, key, len);
    copy[len] = '\0';
    values->items[values->len++] = copy;
    return 0;
}

static int find_captures(const br_regex *regex, br_slice input, captures *values,
                         bool unique, bool entropy_filter, char **error)
{
    capture_context context = {input, values, unique, entropy_filter, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(regex, input, collect_capture, &context, &regex_error);
    if (context.error) {
        free(regex_error);
        regex_error = context.error;
    }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static int key_error(br_result *result, const char *error)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, error, &secret, 1);
}

static int verify_accuweather(const br_scan_ctx *ctx, const char *key,
                              const char *id, br_result *result)
{
    (void)id;
    char url[192];
    /* Upstream concatenates the raw key, including percent signs, into RawQuery. */
    snprintf(url, sizeof(url), "https://dataservice.accuweather.com/locations/v1/cities/autocomplete?apikey=%s&q=----&language=en-us", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 303,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200:
        case 403: result->verified = true; break; /* Permission denied still validates the key. */
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

static int add_part(br_json *parts, const char *name, const char *value)
{
    br_json *string = json_object_new_string(value);
    if (!string) return -1;
    if (json_object_object_add(parts, name, string) != 0) {
        json_object_put(string);
        return -1;
    }
    return 0;
}

static int emit_result(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const char *key, const char *id, verifier check,
                        br_results *out, char **error)
{
    size_t key_len = strlen(key), id_len = id ? strlen(id) : 0;
    br_result result = {.detector_type = detector->type};
    result.raw.data = malloc(key_len);
    result.secret_parts = json_object_new_object();
    if (!result.raw.data || !result.secret_parts) goto memory_error;
    memcpy(result.raw.data, key, key_len);
    result.raw.len = key_len;
    if (add_part(result.secret_parts, "key", key) != 0) goto memory_error;
    if (id) {
        result.raw_v2.data = malloc(key_len + id_len);
        if (!result.raw_v2.data) goto memory_error;
        memcpy(result.raw_v2.data, key, key_len);
        memcpy(result.raw_v2.data + key_len, id, id_len);
        result.raw_v2.len = key_len + id_len;
        if (add_part(result.secret_parts, "id", id) != 0) goto memory_error;
    }
    if (verify && check(ctx, key, id, &result) != 0) goto memory_error;
    if (br_results_push(out, &result) != 0) goto memory_error;
    return 0;
memory_error:
    br_result_clear(&result);
    return fail(error, "out of memory creating detector result");
}

static int valid_scan(const br_detector *detector, br_slice input,
                       br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid detector scan arguments");
    const detector_patterns *patterns = detector->state;
    if (!patterns->key) return fail(error, "uninitialized second-batch detector");
    return 0;
}

static int scan_accuweather(const br_detector *detector, const br_scan_ctx *ctx,
                            bool verify, br_slice input, br_results *out, char **error)
{
    if (valid_scan(detector, input, out, error) != 0) return -1;
    const detector_patterns *patterns = detector->state;
    captures keys = {0};
    int rc = find_captures(patterns->key, input, &keys, true, true, error);
    /* Both versions inherit v1 ProcessMatches: entropy filtering, then unique keys. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i)
        rc = emit_result(detector, ctx, verify, keys.items[i], NULL,
                         verify_accuweather, out, error);
    captures_clear(&keys);
    return rc;
}

static detector_patterns accuweather_v1_patterns, accuweather_v2_patterns;
static const char *const accuweather_keywords[] = {"accuweather"};

static const br_detector accuweather_v1 = {
    .type = 303, .version = 1, .name = "Accuweather", .custom_name = "",
    .description = "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts.",
    .keywords = accuweather_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &accuweather_v1_patterns, .scan = scan_accuweather,
};
static const br_detector accuweather_v2 = {
    .type = 303, .version = 2, .name = "Accuweather", .custom_name = "",
    .description = "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts.",
    .keywords = accuweather_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &accuweather_v2_patterns, .scan = scan_accuweather,
};
static const br_detector *implemented[] = {
    &accuweather_v1, &accuweather_v2, NULL, NULL,
};

static int compile_pattern(const br_detector *detector, const char *capture,
                            bool prefix_required, br_regex **out, char **error)
{
    if (*out) return 0;
    if (!prefix_required) return br_regex_compile(capture, out, error);
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

int br_second_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid second-batch outputs");
    if (br_adafruitio_init(&implemented[2], error) != 0 ||
        br_adobeio_init(&implemented[3], error) != 0 ||
        compile_pattern(&accuweather_v1, "([a-z0-9A-Z\\%]{35})\\b", true,
                        &accuweather_v1_patterns.key, error) != 0 ||
        compile_pattern(&accuweather_v2, "\\b([a-zA-Z0-9]{32})\\b", true,
                        &accuweather_v2_patterns.key, error) != 0)
        return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_second_batch_is_default(const br_detector *detector)
{
    if (!detector || (detector->custom_name && detector->custom_name[0])) return false;
    return (detector->type == 303 && (detector->version == 1 || detector->version == 2)) ||
           (detector->type == 390 && detector->version == 0);
}
