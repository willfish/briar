/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/webexbot/webexbot.go.
 * Unique tokens keep first-seen order; Go map iteration is unstable. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *key_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

typedef struct {
    char *data;
    size_t len;
} webex_text;

typedef struct {
    webex_text type;
    webex_text username;
    char *cause;
    bool failed;
} webex_profile;

/* Exact document +1 is ordinary. Any other document or visitor code is fatal. */
__attribute__((weak)) int br_webexbot_json_document(br_slice body, const char *read_error,
                                                    br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_webexbot_each_member(br_slice object, br_json_member_fn callback,
                                                  void *user)
{
    return br_json_each_member(object, callback, user);
}

__attribute__((weak)) int br_webexbot_each_element(br_slice array, br_json_element_fn callback,
                                                   void *user)
{
    return br_json_each_element(array, callback, user);
}

static int webex_note(webex_profile *profile, br_json *value, const char *field,
                      const char *expected)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, expected, &cause) != 0) {
        free(cause);
        return -1;
    }
    /* First ordinary type error sticks even when its diagnostic is NULL. */
    if (!profile->failed) {
        profile->failed = true;
        profile->cause = cause;
    } else free(cause);
    return 0;
}

static int webex_keep(webex_text *slot, br_json *value)
{
    br_slice text = br_json_text(value);
    if (text.len == SIZE_MAX) return -1;
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->data);
    slot->data = copy;
    slot->len = text.len;
    return 0;
}

static int webex_email(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    (void)encoded;
    webex_profile *profile = user;
    if (!value || json_object_is_type(value, json_type_null) ||
        json_object_is_type(value, json_type_string))
        return 0;
    return webex_note(profile, value, "response.emails", "string");
}

static int webex_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    webex_profile *profile = user;
    const char *field = NULL;
    webex_text *slot = NULL;
    if (br_json_field_name(name, "type")) {
        field = "response.type";
        slot = &profile->type;
    } else if (br_json_field_name(name, "id")) field = "response.id";
    else if (br_json_field_name(name, "displayname")) field = "response.displayName";
    else if (br_json_field_name(name, "nickname")) field = "response.nickName";
    else if (br_json_field_name(name, "username")) {
        field = "response.username";
        slot = &profile->username;
    } else if (br_json_field_name(name, "emails")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_array))
            return webex_note(profile, value, "response.emails", "[]string");
        /* Continue after an ordinary element error. Visitor nonzero stays fatal. */
        return br_webexbot_each_element(encoded, webex_email, profile);
    } else return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return webex_note(profile, value, field, "string");
    return slot && webex_keep(slot, value) != 0 ? -1 : 0;
}

static void webex_clear(webex_profile *profile)
{
    free(profile->type.data);
    free(profile->username.data);
    free(profile->cause);
    profile->type.data = profile->username.data = profile->cause = NULL;
    profile->type.len = profile->username.len = 0;
}

static int decode_profile(br_slice body, const char *read_error, const char **type,
                          size_t *type_len, const char **username, size_t *username_len,
                          char **cause, char **error)
{
    *type = NULL;
    *username = NULL;
    if (type_len) *type_len = 0;
    if (username_len) *username_len = 0;
    br_json *value = NULL;
    size_t end = 0;
    int parsed = br_webexbot_json_document(body, read_error, &value, &end, cause);
    if (parsed == 1) return 1; /* %w is unwrapped: store the inner cause, even if NULL. */
    if (parsed != 0) {
        free(*cause);
        *cause = NULL;
        return fail(error, "cannot decode WebexBot response");
    }
    webex_profile profile = {0};
    int rc = 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        /* JSON null is the zero response. */
    } else if (!json_object_is_type(value, json_type_object)) {
        rc = webex_note(&profile, value, NULL, "webexbot.response");
    } else rc = br_webexbot_each_member((br_slice){body.data, end}, webex_member, &profile);
    json_object_put(value);
    if (rc != 0) {
        /* A later visitor +1 is fatal even after a saved ordinary cause. */
        webex_clear(&profile);
        return fail(error, "cannot visit WebexBot response");
    }
    if (profile.failed) {
        *cause = profile.cause;
        profile.cause = NULL;
        webex_clear(&profile);
        return 1;
    }
    if (!profile.type.data && !(profile.type.data = strdup(""))) rc = -1;
    if (rc == 0 && !profile.username.data && !(profile.username.data = strdup(""))) rc = -1;
    if (rc != 0) {
        webex_clear(&profile);
        return fail(error, "cannot copy WebexBot profile");
    }
    *type = profile.type.data;
    *username = profile.username.data;
    if (type_len) *type_len = profile.type.len;
    if (username_len) *username_len = profile.username.len;
    return 0;
}

static int extra_put(br_result *result, const char *key, const char *value, size_t len,
                     char **error)
{
    if (!result->extra_data && !(result->extra_data = json_object_new_object()))
        return fail(error, "cannot create WebexBot metadata");
    br_json *item = json_object_new_string_len(value ? value : "", (int)len);
    if (!item || json_object_object_add(result->extra_data, key, item) != 0) {
        json_object_put(item);
        return fail(error, "cannot create WebexBot metadata");
    }
    return 0;
}

static int verify_webex(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_slice redact = {(const unsigned char *)key, strlen(key)};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &redact, 1) == 0
            ? 0 : fail(error, "cannot set WebexBot verification error");
    char authorization[160];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return fail(error, "cannot format WebexBot authorization");
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://webexapis.com/v1/people/me",
        .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    char *cause = NULL;
    char message[64];
    int rc = 0;
    if (sent) cause = transport_error;
    else if (response.status == 200) {
        const char *type = NULL, *username = NULL;
        size_t type_len = 0, username_len = 0;
        int decoded = decode_profile(response.body, response.body_error, &type, &type_len,
                                     &username, &username_len, &cause, error);
        if (decoded < 0) rc = -1;
        else {
            result->verified = true;
            if (!decoded && (extra_put(result, "type", type, type_len, error) != 0 ||
                             extra_put(result, "username", username, username_len, error) != 0))
                rc = -1;
        }
        free((void *)type);
        free((void *)username);
    } else if (response.status != 401) {
        snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        cause = message;
    }
    if (!rc && br_result_set_verification_error(result, cause, &redact, 1) != 0)
        rc = fail(error, "cannot set WebexBot verification error");
    if (cause != transport_error && cause != message) free(cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_webex(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized WebexBot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        char redacted[16];
        if (keys.lengths[i] < 5 || snprintf(redacted, sizeof(redacted), "%.5s...", keys.items[i]) < 0 ||
            br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0 ||
            !(result.redacted = strdup(redacted)) ||
            (!verify && !(result.extra_data = json_object_new_object()))) {
            fail(&owned_error, "cannot create WebexBot result");
            outcome = -1;
        } else if (verify && verify_webex(ctx, keys.items[i], &result, &owned_error) != 0)
            outcome = -1;
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append WebexBot result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"spark", "webex"};
static br_detector webex = {
    .type = 1033, .version = 0, .name = "WebexBot", .custom_name = "",
    .description = "Webex bot allows applications to interact with users in Webex spaces.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_webex,
};

int br_webexbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WebexBot detector output");
    *out = NULL;
    if (!key_re && br_regex_compile(
            "([a-zA-Z0-9]{64}_[a-zA-Z0-9]{4}_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})",
            &key_re, error) != 0)
        return -1;
    webex.state = key_re;
    *out = &webex;
    return 0;
}
