/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newrelicuserkey/newrelicuserkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Mandatory when verification ran, including a nil cause. No secrets. */
static int set_cause(br_result *result, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return fail(error, "cannot record NewRelicUserKey verification error");
    return 0;
}

static int add_string_len(br_json *object, const char *name, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value ? value : "", (int)len);
    if (!part) return -1;
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int redact(br_result *result, br_slice key, char **error)
{
    if (!key.data || key.len < 8) return fail(error, "cannot allocate NewRelicUserKey redaction");
    char shown[12];
    memcpy(shown, key.data, 8);
    memcpy(shown + 8, "...", 4);
    result->redacted = strdup(shown);
    if (!result->redacted) return fail(error, "cannot allocate NewRelicUserKey redaction");
    return 0;
}

/* Extra, including user_id, and the region secret part precede the setter. */
static int record_verified(br_result *result, const char *region, const char *user_id,
                           size_t user_len, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return fail(error, "cannot create NewRelicUserKey metadata");
    if (add_string_len(result->extra_data, "region", region, strlen(region)) != 0)
        return fail(error, "cannot record NewRelicUserKey region");
    if (add_string_len(result->extra_data, "user_id", user_id, user_len) != 0)
        return fail(error, "cannot record NewRelicUserKey user id");
    if (add_string_len(result->secret_parts, "region", region, strlen(region)) != 0)
        return fail(error, "cannot record NewRelicUserKey region");
    return 0;
}

static int copy_bytes(const void *text, size_t len, char **out)
{
    if (len == SIZE_MAX) return -1;
    char *owned = malloc(len + 1);
    if (!owned) return -1;
    if (len) memcpy(owned, text, len);
    owned[len] = '\0';
    *out = owned;
    return 0;
}

static int with_region(const char *head, const char *region, const char *inner, char **out)
{
    static const char mid[] = ": ";
    size_t head_len = strlen(head), region_len = strlen(region), inner_len = strlen(inner);
    if (head_len > SIZE_MAX - sizeof(mid) || region_len > SIZE_MAX - sizeof(mid) - head_len ||
        inner_len > SIZE_MAX - sizeof(mid) - head_len - region_len) return -1;
    size_t n = head_len + region_len + sizeof(mid) - 1 + inner_len;
    char *text = malloc(n + 1);
    if (!text) return -1;
    size_t at = 0;
    memcpy(text + at, head, head_len);
    at += head_len;
    memcpy(text + at, region, region_len);
    at += region_len;
    memcpy(text + at, mid, sizeof(mid) - 1);
    at += sizeof(mid) - 1;
    memcpy(text + at, inner, inner_len + 1);
    *out = text;
    return 0;
}

static int outer_error(const char *region, const char *inner, char **out)
{
    return with_region("error verifying region ", region, inner, out);
}

static int join_errors(char *const *parts, size_t n, char **out)
{
    *out = NULL;
    if (!n) return 0;
    size_t total = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t len = strlen(parts[i]);
        if (i && total == SIZE_MAX - 1) return -1;
        if (i) ++total;
        if (len > SIZE_MAX - total - 1) return -1;
        total += len;
    }
    char *joined = malloc(total + 1);
    if (!joined) return -1;
    size_t at = 0;
    for (size_t i = 0; i < n; ++i) {
        if (i) joined[at++] = '\n';
        size_t len = strlen(parts[i]);
        memcpy(joined + at, parts[i], len);
        at += len;
    }
    joined[at] = '\0';
    *out = joined;
    return 0;
}

static void free_parts(char **parts, size_t n)
{
    for (size_t i = 0; i < n; ++i) free(parts[i]);
}

typedef struct {
    char *user_id;
    size_t user_len;
    bool have_user;
    char *cause;
} user_fields;

static void clear_user(user_fields *fields)
{
    free(fields->user_id);
    fields->user_id = NULL;
    fields->user_len = 0;
    fields->have_user = false;
}

/* Inclusion tests may replace the user-id copy. Production uses copy_bytes. */
#ifndef user_id_copy
#define user_id_copy copy_bytes
#endif

static int set_user(user_fields *fields, const void *text, size_t len)
{
    char *copy = NULL;
    if (user_id_copy(text, len, &copy) != 0) return -1;
    free(fields->user_id);
    fields->user_id = copy;
    fields->user_len = len;
    fields->have_user = true;
    return 0;
}

static int type_error(user_fields *fields, br_json *value, const char *field, const char *expected)
{
    if (fields->cause) return 0;
    return br_json_type_cause(value, field, expected, &fields->cause) == 0 ? 0 : -1;
}

/* A stored cause does not stop the walk. A later valid value is still stored.
 * Null does not clear a string already stored. The first cause stays. */
static int visit_user_id(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    user_fields *fields = user;
    if (!br_json_field_name(name, "userid")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return type_error(fields, value, ".data.requestContext.userId", "string");
    br_slice text = br_json_text(value);
    return set_user(fields, text.data, text.len);
}

static int visit_request_context(void *user, br_slice name, br_json *value, br_slice encoded)
{
    user_fields *fields = user;
    if (!br_json_field_name(name, "requestcontext")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        static const char expected[] = "struct { UserID string \"json:\\\"userId\\\"\" }";
        return type_error(fields, value, ".data.requestContext", expected);
    }
    return br_json_each_member(encoded, visit_user_id, fields);
}

static int visit_data(void *user, br_slice name, br_json *value, br_slice encoded)
{
    user_fields *fields = user;
    if (!br_json_field_name(name, "data")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        static const char expected[] =
            "struct { RequestContext struct { UserID string \"json:\\\"userId\\\"\" } \"json:\\\"requestContext\\\"\" }";
        return type_error(fields, value, "graphqlResponse.data", expected);
    }
    return br_json_each_member(encoded, visit_request_context, fields);
}

/* 0 verified, 1 ordinary cause (*cause may be NULL), -1 fatal. */
static int decode_user(br_slice body, const char *read_error, char **user_id, size_t *user_len,
                       char **cause, char **error)
{
    *user_id = NULL;
    *user_len = 0;
    *cause = NULL;
    /* A body read error is a decode failure even when the bytes would parse. */
    if (read_error) return copy_bytes(read_error, strlen(read_error), cause) == 0 ? 1 :
        fail(error, "cannot decode NewRelicUserKey verification response");
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, NULL, &root, &end, cause);
    if (rc < 0) return fail(error, "cannot decode NewRelicUserKey verification response");
    /* A NULL decode cause is still an error. Do not invent EOF text. */
    if (rc > 0) {
        json_object_put(root);
        return 1;
    }
    user_fields fields = {0};
    if (root && !json_object_is_type(root, json_type_null)) {
        if (json_object_is_type(root, json_type_object)) {
            int visit = br_json_each_member((br_slice){body.data, end}, visit_data, &fields);
            if (visit != 0) {
                clear_user(&fields);
                free(fields.cause);
                json_object_put(root);
                return fail(error, "cannot decode NewRelicUserKey verification response");
            }
        } else if (type_error(&fields, root, NULL, "newrelicuserkey.graphqlResponse") != 0) {
            json_object_put(root);
            return fail(error, "cannot decode NewRelicUserKey verification response");
        }
    }
    json_object_put(root);
    /* A later stored user id is not published when the first cause remains. */
    if (fields.cause) {
        clear_user(&fields);
        *cause = fields.cause;
        return 1;
    }
    if (!fields.have_user && set_user(&fields, "", 0) != 0)
        return fail(error, "cannot decode NewRelicUserKey verification response");
    *user_id = fields.user_id;
    *user_len = fields.user_len;
    return 0;
}

/* 1 verified, 0 continue, -1 fatal. *text is an owned region error, or NULL. */
static int verify_region(const br_scan_ctx *ctx, br_slice key, const char *region, const char *url,
                         int32_t type, char **text, char **user_id, size_t *user_len, char **error)
{
    *text = NULL;
    *user_id = NULL;
    *user_len = 0;
    if (key.len != 32 || !key.data) return fail(error, "cannot verify NewRelicUserKey key");
    char insert[33];
    memcpy(insert, key.data, 32);
    insert[32] = '\0';
    static const char body_text[] = "{\"query\": \"{ requestContext { userId } }\"}";
    const br_header headers[] = {
        {.name = "Content-Type", .value = "application/json"},
        {.name = "Api-Key", .value = insert},
    };
    const br_http_request request = {
        .method = "POST",
        .url = url,
        .headers = headers,
        .nheaders = 2,
        .body = {(const unsigned char *)body_text, sizeof(body_text) - 1},
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int status = response.status;
    const char *body_error = response.body_error;
    br_slice body = response.body;
    int rc = 0;
    char *inner = NULL;
    char *decoded_user = NULL;
    size_t decoded_len = 0;
    bool verified = false;
    if (sent != 0) {
        if (send_error) {
            static const char head[] = "error making request: ";
            size_t head_len = sizeof(head) - 1, detail_len = strlen(send_error);
            if (detail_len > SIZE_MAX - head_len - 1 ||
                !(inner = malloc(head_len + detail_len + 1)))
                rc = fail(error, "cannot record NewRelicUserKey verification error");
            else {
                memcpy(inner, head, head_len);
                memcpy(inner + head_len, send_error, detail_len + 1);
            }
        }
    } else if (status == 401 || status == 403) {
        /* Quiet nil. Try the other region. */
    } else if (status != 200) {
        char status_text[64];
        int n = snprintf(status_text, sizeof(status_text),
                         "unexpected status code for region %s: %d", region, status);
        if (n < 0 || (size_t)n >= sizeof(status_text))
            rc = fail(error, "cannot format NewRelicUserKey verification status");
        else if (copy_bytes(status_text, (size_t)n, &inner) != 0)
            rc = fail(error, "cannot record NewRelicUserKey verification error");
    } else {
        char *decode = NULL;
        int decoded = decode_user(body, body_error, &decoded_user, &decoded_len, &decode, error);
        if (decoded < 0) rc = -1;
        else if (decoded > 0) {
            if (decode) {
                char *wrapped = NULL;
                if (with_region("error decoding response for region ", region, decode, &wrapped) != 0)
                    rc = fail(error, "cannot record NewRelicUserKey verification error");
                else inner = wrapped;
                free(decode);
            }
        } else verified = true;
    }
    if (rc == 0 && inner && outer_error(region, inner, text) != 0)
        rc = fail(error, "cannot record NewRelicUserKey verification error");
    /* Release once while the key header and body literal are still alive. */
    br_http_release(ctx, &response);
    free(inner);
    free(send_error);
    if (rc != 0) {
        free(*text);
        *text = NULL;
        free(decoded_user);
        return -1;
    }
    if (verified) {
        *user_id = decoded_user;
        *user_len = decoded_len;
        return 1;
    }
    free(decoded_user);
    return 0;
}

static int verify_key(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char *const regions[] = {"us", "eu"};
    static const char *const urls[] = {
        "https://api.newrelic.com/graphql",
        "https://api.eu.newrelic.com/graphql",
    };
    char *parts[2] = {0};
    size_t nparts = 0;
    const char *verified = NULL;
    char *user_id = NULL;
    size_t user_len = 0;
    int rc = 0;
    if (!ctx) {
        static const char inner[] = "error constructing request: net/http: nil Context";
        for (size_t i = 0; i < 2; ++i) {
            if (outer_error(regions[i], inner, &parts[nparts]) != 0) {
                rc = fail(error, "cannot record NewRelicUserKey verification error");
                break;
            }
            ++nparts;
        }
    } else {
        for (size_t i = 0; rc == 0 && i < 2 && !verified; ++i) {
            char *text = NULL, *found = NULL;
            size_t found_len = 0;
            int verdict = verify_region(ctx, key, regions[i], urls[i], result->detector_type,
                                        &text, &found, &found_len, error);
            if (verdict < 0) rc = -1;
            else if (verdict > 0) {
                verified = regions[i];
                user_id = found;
                user_len = found_len;
            } else if (text) parts[nparts++] = text;
        }
    }
    if (rc != 0) {
        free_parts(parts, nparts);
        free(user_id);
        return rc;
    }
    if (verified) {
        free_parts(parts, nparts);
        result->verified = true;
        if (record_verified(result, verified, user_id, user_len, error) != 0) {
            free(user_id);
            return -1;
        }
        free(user_id);
        return set_cause(result, NULL, error);
    }
    char *joined = NULL;
    if (join_errors(parts, nparts, &joined) != 0) {
        free_parts(parts, nparts);
        return fail(error, "cannot record NewRelicUserKey verification error");
    }
    free_parts(parts, nparts);
    rc = set_cause(result, joined, error);
    free(joined);
    return rc;
}

static int scan_user(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized NewRelicUserKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keyword is an engine hint. Keep every match, including duplicates.
     * Map order is unspecified; this scanner uses US then EU. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create NewRelicUserKey finding");
            rc = -1;
        } else if (redact(&result, key, &owned_error) != 0) {
            rc = -1;
        } else if (verify && verify_key(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append NewRelicUserKey finding");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"nrak-"};
static br_detector user = {
    .type = 1066,
    .version = 0,
    .name = "NewRelicUserKey",
    .custom_name = "",
    .description = "A New Relic User API Key is an authentication token used to query data from New Relic via the NerdGraph API or REST API, allowing users to access account data and perform read operations securely. It is primarily used for interacting with New Relic\xe2\x80\x99s query and configuration services.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_user,
};

int br_newrelicuserkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid NewRelicUserKey detector output");
    *out = NULL;
    if (!user.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(NRAK-[A-Z0-9]{27})\\b", &regex, error) != 0)
            return -1;
        user.state = regex;
    }
    *out = &user;
    return 0;
}
