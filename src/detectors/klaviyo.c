/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/klaviyo/klaviyo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const keywords[] = {"pk_"};
static const char auth_prefix[] = "Klaviyo-API-Key ";
static const char profiles_url[] = "https://a.klaviyo.com/api/profiles";

static br_detector klaviyo = {
    .name = "Klaviyo",
    .custom_name = "",
    .description = "Klaviyo is a marketing automation platform. Klaviyo API keys can be used to access and modify marketing data and configurations.",
    .keywords = keywords,
    .nkeywords = 1,
    .type = 935,
    .max_secret_size = -1,
    .max_credential_span = -1,
    .start_offset = -1,
};

static int set_error(br_result *result, const char *cause, const char *key)
{
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    return br_result_set_verification_error(result, cause, &secret, 1) == 0 ? 0 : -1;
}

static br_slice number_text(br_slice encoded)
{
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    return encoded;
}

/* Go unmarshals status from the original token into int64, not a float. */
static bool int64_token(br_slice number)
{
    size_t at = 0;
    bool negative = number.len && number.data[0] == '-';
    if (negative) ++at;
    if (at == number.len) return false;
    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    uint64_t magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false;
        uint64_t digit = (uint64_t)(c - '0');
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    return true;
}

/* An ordinary typed mismatch is a flag. It must not be a callback
 * return: that would stop the source-order walk and hide a later fatal. */
typedef struct {
    size_t count;
    bool mismatch;
} klaviyo_json;

static int note_mismatch(klaviyo_json *state)
{
    state->mismatch = true;
    return 0;
}

static int read_string_field(br_json *value, klaviyo_json *state)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (json_object_is_type(value, json_type_string)) return 0;
    return note_mismatch(state);
}

static int read_status(br_json *value, br_slice encoded, klaviyo_json *state)
{
    /* Null leaves the zero int. A later valid integer replaces it; either
     * invalid value fails the decode, so last-wins is only observable when both are valid. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
        return note_mismatch(state);
    return int64_token(number_text(encoded)) ? 0 : note_mismatch(state);
}

static int read_source_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (!br_json_field_name(name, "pointer")) return 0;
    return read_string_field(value, user);
}

static int read_source(br_json *value, br_slice encoded, klaviyo_json *state)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object)) return note_mismatch(state);
    return br_json_each_member(encoded, read_source_field, state);
}

static int read_error_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    klaviyo_json *state = user;
    if (br_json_field_name(name, "status")) return read_status(value, encoded, state);
    if (br_json_field_name(name, "source")) return read_source(value, encoded, state);
    if (br_json_field_name(name, "id") || br_json_field_name(name, "code") ||
        br_json_field_name(name, "title") || br_json_field_name(name, "detail"))
        return read_string_field(value, state);
    return 0; /* Unknown members, including out-of-range numbers, are ignored. */
}

static int read_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    klaviyo_json *state = user;
    if (value && !json_object_is_type(value, json_type_null) &&
        !json_object_is_type(value, json_type_object))
        return note_mismatch(state);
    if (value && json_object_is_type(value, json_type_object)) {
        int rc = br_json_each_member(encoded, read_error_field, state);
        if (rc) return rc;
    }
    ++state->count; /* A null element is a zero struct and still lengthens the slice. */
    return 0;
}

static int read_errors(void *user, br_slice name, br_json *value, br_slice encoded)
{
    klaviyo_json *state = user;
    if (!br_json_field_name(name, "errors")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        state->count = 0; /* Missing stays zero; null replaces a prior slice with nil. */
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) return note_mismatch(state);
    state->count = 0;
    return br_json_each_element(encoded, read_element, state);
}

static int classify_403(br_slice body, const char *body_error, const char *key, br_result *result)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_json_first_document(body, body_error, &root, &end, &cause);
    free(cause); /* Decode text is never published; the static message replaces it. */
    if (rc < 0) {
        json_object_put(root);
        return -1;
    }
    klaviyo_json state = {0};
    bool decoded = false;
    if (rc == 0) {
        if (!root || json_object_is_type(root, json_type_null)) decoded = true;
        else if (json_object_is_type(root, json_type_object)) {
            /* first_document +1 stays an ordinary decode cause above. Any
             * nonzero from the walk, including +1, is fatal and is not that cause. */
            int walk = br_json_each_member((br_slice){body.data, end}, read_errors, &state);
            if (walk != 0) {
                json_object_put(root);
                return -1;
            }
            decoded = !state.mismatch;
        }
    }
    json_object_put(root);
    if (!decoded) return set_error(result, "unexpected API JSON response", key);
    if (state.count > 0) {
        result->verified = true;
        return 0;
    }
    return set_error(result, "errors expected", key);
}

static int verify_klaviyo(const br_scan_ctx *ctx, const char *key, const char *url,
                           br_result *result)
{
    size_t key_len = strlen(key);
    if (key_len != 37 && key_len != 44) return -1;
    /* Headers exist only after NewRequestWithContext succeeds. */
    char authorization[sizeof(auth_prefix) + 44];
    memcpy(authorization, auth_prefix, sizeof(auth_prefix) - 1);
    memcpy(authorization + sizeof(auth_prefix) - 1, key, key_len + 1);
    const br_header headers[] = {
        {"Revision", "2023-02-22"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET",
        .url = url,
        .headers = headers,
        .nheaders = 2,
        .profile = BR_HTTP_SANE,
        .detector_type = 935,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        rc = set_error(result, transport_error, key); /* NULL is a checked no-op; do not invent a cause. */
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status == 403)
        rc = classify_403(response.body, response.body_error, key, result);
    else if (response.status != 401) {
        char message[64];
        int formatted = snprintf(message, sizeof(message),
                                 "unexpected HTTP response status %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = -1; /* Formatter failure is fatal before the setter. */
        else
            rc = set_error(result, message, key);
    }
    br_http_release(ctx, &response); /* One release for every attempt, including setter failure. */
    free(transport_error);
    return rc;
}

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_klaviyo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Klaviyo scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Capture runs even when verify is set and ctx is NULL. Any nonzero,
     * including +1, is fatal before a nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating Klaviyo result");
        if (rc == 0 && verify) {
            /* Constant URL, then the constructor. It is not allocated. */
            const char *request_url = profiles_url;
            if (!ctx) {
                /* "net/http: nil Context" drops only this candidate. */
                (void)request_url;
                br_result_clear(&result);
                continue;
            }
            if (verify_klaviyo(ctx, keys.items[i], request_url, &result) != 0)
                rc = fail(&owned_error, "out of memory sanitizing verification error");
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending Klaviyo result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

int br_klaviyo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Klaviyo detector");
        return -1;
    }
    if (!klaviyo.state) {
        br_regex *regex = NULL;
        if (br_regex_compile(
                "\\b(pk_([0-9a-f]{34}|[A-Za-z0-9]{6}_[0-9a-f]{34}))\\b",
                &regex, error) != 0)
            return -1;
        klaviyo.state = regex;
    }
    klaviyo.scan = scan_klaviyo;
    *out = &klaviyo;
    return 0;
}
