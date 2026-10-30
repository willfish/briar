/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sentrytoken/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char sentry_url[] = "https://sentry.io/api/0/auth/validate/";
static const char sentry_forbidden[] = "You do not have permission to perform this action.";

static int sentry_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int fmt_add(char **out, size_t *len, size_t *cap, const void *bytes, size_t n)
{
    if (*len > SIZE_MAX - n - 1) return -1;
    if (*len + n + 1 > *cap) {
        size_t next = *cap ? *cap : 64;
        while (next < *len + n + 1) {
            if (next > SIZE_MAX / 2) return -1;
            next *= 2;
        }
        char *grown = realloc(*out, next);
        if (!grown) return -1;
        *out = grown;
        *cap = next;
    }
    if (n) memcpy(*out + *len, bytes, n);
    *len += n;
    (*out)[*len] = '\0';
    return 0;
}

static int fmt_str(char **out, size_t *len, size_t *cap, const char *text)
{
    return fmt_add(out, len, cap, text, strlen(text));
}

static int encoded_kind(br_slice encoded, unsigned char *kind)
{
    size_t at = 0;
    while (at < encoded.len && (encoded.data[at] == ' ' || encoded.data[at] == '\t' ||
                                encoded.data[at] == '\n' || encoded.data[at] == '\r'))
        ++at;
    if (at >= encoded.len) return 0;
    *kind = encoded.data[at];
    return 1;
}

typedef struct {
    unsigned char *key;
    size_t key_len;
    br_slice encoded;
} sentry_survivor;

typedef struct {
    sentry_survivor *items;
    size_t len, cap;
} sentry_survivors;

static int keys_representable(br_slice encoded);

/* Last duplicate wins by decoded key bytes. Case is significant, matching map[string]. */
static int keep_survivor(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)value;
    sentry_survivors *kept = user;
    for (size_t i = 0; i < kept->len; ++i) {
        if (kept->items[i].key_len == name.len &&
            (!name.len || !memcmp(kept->items[i].key, name.data, name.len))) {
            kept->items[i].encoded = encoded;
            return 0;
        }
    }
    if (kept->len == kept->cap) {
        size_t cap = kept->cap ? kept->cap * 2 : 4;
        if (cap < kept->cap) return -1;
        void *grown = realloc(kept->items, cap * sizeof(*kept->items));
        if (!grown) return -1;
        kept->items = grown;
        kept->cap = cap;
    }
    unsigned char *key = malloc(name.len ? name.len : 1);
    if (!key) return -1;
    if (name.len) memcpy(key, name.data, name.len);
    kept->items[kept->len++] = (sentry_survivor){key, name.len, encoded};
    return 0;
}

static int reject_nul_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)user;
    (void)index;
    (void)value;
    return keys_representable(encoded);
}

/* String values may contain NUL. Only a surviving map key that does is unrepresentable. */
static int keys_representable(br_slice encoded)
{
    unsigned char kind = 0;
    if (!encoded_kind(encoded, &kind)) return 0;
    if (kind == '[') return br_json_each_element(encoded, reject_nul_element, NULL);
    if (kind != '{') return 0;
    sentry_survivors kept = {0};
    int rc = br_json_each_member(encoded, keep_survivor, &kept);
    for (size_t i = 0; rc == 0 && i < kept.len; ++i) {
        for (size_t j = 0; j < kept.items[i].key_len; ++j) {
            if (!kept.items[i].key[j]) {
                rc = -1; /* json-c cannot project this live key. */
                break;
            }
        }
        if (rc == 0) rc = keys_representable(kept.items[i].encoded);
    }
    for (size_t i = 0; i < kept.len; ++i) free(kept.items[i].key);
    free(kept.items);
    return rc == 0 ? 0 : -1;
}

static int contains_phrase(const char *text, size_t len, const char *phrase)
{
    size_t phrase_len = strlen(phrase);
    if (!text || phrase_len > len) return 0;
    for (size_t i = 0; i + phrase_len <= len; ++i)
        if (!memcmp(text + i, phrase, phrase_len)) return 1;
    return 0;
}

/* encoding/json into interface{}, then fmt %v. Map keys are sorted. Array
 * elements are joined by one space, which can synthesize the forbidden phrase. */
static int sentry_format(br_json *value, char **out, size_t *len, size_t *cap, int depth,
                          br_slice encoded)
{
    if (depth > 64) return -1;
    if (encoded.len && keys_representable(encoded) != 0) return -1;
    if (!value || json_object_is_type(value, json_type_null))
        return fmt_str(out, len, cap, "<nil>");
    enum json_type kind = json_object_get_type(value);
    if (kind == json_type_boolean)
        return fmt_str(out, len, cap, json_object_get_boolean(value) ? "true" : "false");
    if (kind == json_type_int || kind == json_type_double) {
        const char *text = json_object_get_string(value);
        return text ? fmt_str(out, len, cap, text) : -1;
    }
    if (kind == json_type_string) {
        br_slice text = br_json_text(value);
        return fmt_add(out, len, cap, text.data, text.len);
    }
    if (kind == json_type_array) {
        if (fmt_add(out, len, cap, "[", 1) != 0) return -1;
        size_t n = json_object_array_length(value);
        for (size_t i = 0; i < n; ++i) {
            if (i && fmt_add(out, len, cap, " ", 1) != 0) return -1;
            if (sentry_format(json_object_array_get_idx(value, i), out, len, cap, depth + 1,
                              (br_slice){0}) != 0)
                return -1;
        }
        return fmt_add(out, len, cap, "]", 1);
    }
    if (kind != json_type_object) return -1;
    size_t n = json_object_object_length(value);
    const char **keys = n ? calloc(n, sizeof(*keys)) : NULL;
    if (n && !keys) return -1;
    size_t seen = 0;
    json_object_object_foreach(value, key, ignored) {
        (void)ignored;
        if (seen < n) keys[seen++] = key;
    }
    if (seen != n) {
        free(keys);
        return -1;
    }
    for (size_t i = 1; i < n; ++i) {
        const char *insert = keys[i];
        size_t j = i;
        while (j && strcmp(keys[j - 1], insert) > 0) {
            keys[j] = keys[j - 1];
            --j;
        }
        keys[j] = insert;
    }
    int rc = fmt_str(out, len, cap, "map[");
    for (size_t i = 0; rc == 0 && i < n; ++i) {
        br_json *child = NULL;
        if (i && fmt_add(out, len, cap, " ", 1) != 0) rc = -1;
        else if (fmt_str(out, len, cap, keys[i]) != 0 || fmt_add(out, len, cap, ":", 1) != 0)
            rc = -1;
        else if (!json_object_object_get_ex(value, keys[i], &child) ||
                 sentry_format(child, out, len, cap, depth + 1, (br_slice){0}) != 0)
            rc = -1;
    }
    if (rc == 0) rc = fmt_add(out, len, cap, "]", 1);
    free(keys);
    return rc;
}

static int sentry_verify(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    /* Authorization is complete before NewRequestWithContext. A nil context is
     * that constructor error, not a send and not a dropped finding. */
    size_t token_len = strlen(token);
    if (token_len > SIZE_MAX - 8) return -1;
    char *authorization = malloc(7 + token_len + 1);
    if (!authorization) return -1;
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token, token_len + 1);
    br_slice secret = {(const unsigned char *)token, token_len};
    if (!ctx) {
        int rc = br_result_set_verification_error(result, "net/http: nil Context", &secret, 1);
        free(authorization);
        return rc == 0 ? 0 : -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = sentry_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char *owned_cause = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error; /* NULL diagnostic stays NULL. */
    } else if (response.status == 200) {
        result->verified = true; /* Body and drain errors are ignored. */
    } else if (response.status == 403) {
        br_json *document = NULL;
        size_t end = 0;
        int decoded = br_json_first_document(response.body, response.body_error,
                                             &document, &end, &owned_cause);
        if (decoded < 0 || decoded > 1) {
            json_object_put(document);
            br_http_release(ctx, &response);
            free(send_error);
            free(owned_cause);
            free(authorization);
            return -1; /* Document +2 is fatal, not an ordinary decode error. */
        }
        if (decoded == 1) {
            cause = owned_cause;
        } else {
            br_slice consumed = {response.body.data, end};
            int numbers = br_json_check_float64_numbers(consumed, &owned_cause);
            if (numbers < 0 || numbers > 1) {
                json_object_put(document);
                br_http_release(ctx, &response);
                free(send_error);
                free(owned_cause);
                free(authorization);
                return -1;
            }
            if (numbers == 1) {
                cause = owned_cause;
                json_object_put(document);
            } else {
                char *formatted = NULL;
                size_t len = 0, cap = 0;
                int formatted_rc = sentry_format(document, &formatted, &len, &cap, 0, consumed);
                json_object_put(document);
                if (formatted_rc != 0) {
                    free(formatted);
                    br_http_release(ctx, &response);
                    free(send_error);
                    free(owned_cause);
                    free(authorization);
                    return -1;
                }
                if (contains_phrase(formatted, len, sentry_forbidden)) result->verified = true;
                free(formatted);
            }
        }
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error),
                 "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(owned_cause);
    free(send_error);
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int sentry_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sentry_fail(error, "invalid or uninitialized SentryToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source map keeps one copy. First-seen order is one valid map order. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = sentry_fail(&owned_error, "cannot create SentryToken result");
        else if (verify && sentry_verify(ctx, keys.items[i], &result) != 0)
            rc = sentry_fail(&owned_error, "cannot verify SentryToken");
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = sentry_fail(&owned_error, "cannot append SentryToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char sentry_description[] =
    "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. "
    "Sentry tokens can be used to access and manage projects and organizations within Sentry.";

static const char *const sentry_v1_keywords[] = {"sentry"};
static br_detector sentry_v1 = {
    .type = 87, .version = 1, .name = "SentryToken", .custom_name = "",
    .description = sentry_description,
    .keywords = sentry_v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sentry_scan,
};

static const char *const sentry_v2_keywords[] = {"sentry", "sntryu"};
static br_regex *sentry_v2_regex;
static br_detector sentry_v2 = {
    .type = 87, .version = 2, .name = "SentryToken", .custom_name = "",
    .description = sentry_description,
    .keywords = sentry_v2_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sentry_scan,
};

int br_sentrytoken_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sentry_fail(error, "invalid SentryToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&sentry_v1, "\\b([a-f0-9]{64})\\b", error) != 0) return -1;
    *out = &sentry_v1;
    return 0;
}

int br_sentrytoken_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sentry_fail(error, "invalid SentryToken detector output");
    *out = NULL;
    if (!sentry_v2_regex &&
        br_regex_compile("\\b(sntryu_[a-f0-9]{64})\\b", &sentry_v2_regex, error) != 0)
        return -1;
    sentry_v2.state = sentry_v2_regex;
    *out = &sentry_v2;
    return 0;
}
