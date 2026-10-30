/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/telegrambottoken/telegrambottoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

enum { TG_KEEP = 0, TG_DROP = 1, TG_FATAL = -1 };

static int tg_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return TG_FATAL;
}

typedef struct {
    bool ok, saw_ok, saw_result, result_present, failed;
    br_json *username;
    char *cause;
} tg_fields;

static void tg_keep(tg_fields *fields, char *cause)
{
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = cause;
    } else free(cause);
}

/* 0 is a completed diagnostic, even when cause is NULL. Every other code is fatal. */
__attribute__((weak)) int br_telegrambottoken_type_cause(br_json *value, const char *field,
                                                         const char *expected, char **cause)
{
    return br_json_type_cause(value, field, expected, cause);
}

static int tg_note(tg_fields *fields, br_json *value, const char *field, const char *expected)
{
    char *cause = NULL;
    int typed = br_telegrambottoken_type_cause(value, field, expected, &cause);
    if (typed != 0) {
        free(cause);
        return typed;
    }
    tg_keep(fields, cause);
    return 0;
}

static int tg_user(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    tg_fields *fields = user;
    if (br_json_field_name(name, "username")) {
        /* Null into a string preserves the previous value, including empty. */
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return tg_note(fields, value, "userResponse.Username", "string");
        br_json *copy = json_object_get(value);
        if (!copy) return -1;
        json_object_put(fields->username);
        fields->username = copy;
        return 0;
    }
    if (br_json_field_name(name, "is_bot") && value &&
        !json_object_is_type(value, json_type_boolean) &&
        !json_object_is_type(value, json_type_null))
        return tg_note(fields, value, "userResponse.IsBot", "bool");
    return 0;
}

static int tg_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    tg_fields *fields = user;
    if (br_json_field_name(name, "ok")) {
        fields->saw_ok = true;
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_boolean))
            return tg_note(fields, value, "apiResponse.Ok", "bool");
        fields->ok = json_object_get_boolean(value);
        return 0;
    }
    if (!br_json_field_name(name, "result")) return 0;
    fields->saw_result = true;
    if (!value || json_object_is_type(value, json_type_null)) {
        fields->result_present = false;
        json_object_put(fields->username);
        fields->username = NULL;
        return 0;
    }
    if (!json_object_is_type(value, json_type_object))
        return tg_note(fields, value, "apiResponse.Result", "*telegrambottoken.userResponse");
    fields->result_present = true;
    return br_json_each_member(encoded, tg_user, fields);
}

__attribute__((weak)) int br_telegrambottoken_json_document(br_slice body, const char *read_error,
                                                             br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_telegrambottoken_each_member(br_slice object, br_json_member_fn callback,
                                                          void *user)
{
    return br_json_each_member(object, callback, user);
}

static int tg_username(br_slice body, const char *read_error, br_json **username, char **cause)
{
    tg_fields fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int parsed = br_telegrambottoken_json_document(body, read_error, &root, &end, &fields.cause);
    int visit = 0;
    if (parsed == 0 && root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object))
            visit = tg_note(&fields, root, NULL, "telegrambottoken.apiResponse");
        else visit = br_telegrambottoken_each_member((br_slice){body.data, end}, tg_member, &fields);
    }
    if (parsed == 0 && visit == 0 && !fields.failed && fields.ok && fields.result_present) {
        if (fields.username) *username = json_object_get(fields.username);
        else *username = json_object_new_string("");
        if (!*username) visit = -1;
    }
    json_object_put(root);
    json_object_put(fields.username);
    if (parsed != 0 && parsed != 1) {
        free(fields.cause);
        return -1;
    }
    if (visit != 0) {
        free(fields.cause);
        return -1;
    }
    *cause = fields.cause;
    return 0;
}

static int tg_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char prefix[] = "https://api.telegram.org/bot";
    static const char suffix[] = "/getMe";
    if (key.len > SIZE_MAX - (sizeof(prefix) - 1 + sizeof(suffix) - 1))
        return tg_fail(error, "Telegram URL size overflow");
    size_t size = sizeof(prefix) - 1 + key.len + sizeof(suffix) - 1;
    char *url = malloc(size + 1);
    if (!url) return tg_fail(error, "cannot allocate Telegram URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
    int outcome = TG_KEEP;
    if (!ctx || memchr(url, '\0', size)) outcome = TG_DROP;
    if (outcome == TG_KEEP) {
        const br_http_request request = {
            .method = "GET", .url = url, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
            response.status >= 200 && response.status < 300) {
            result->verified = true;
            br_json *username = NULL;
            char *cause = NULL;
            int rc = tg_username(response.body, response.body_error, &username, &cause);
            if (rc < 0) outcome = tg_fail(error, "cannot decode Telegram response");
            else if (!cause && username) {
                result->extra_data = json_object_new_object();
                if (!result->extra_data ||
                    json_object_object_add(result->extra_data, "username", username) != 0) {
                    json_object_put(username);
                    outcome = tg_fail(error, "cannot store Telegram username");
                }
            }
            free(cause);
        }
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(url);
    return outcome;
}

static int tg_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tg_fail(error, "invalid or uninitialized TelegramBotToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = TG_KEEP;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            outcome = tg_fail(&owned_error, "cannot create TelegramBotToken result");
        else if (verify)
            outcome = tg_verify(ctx, br_captures_at(&keys, i), &result, &owned_error);
        if (outcome == TG_FATAL) rc = -1;
        if (outcome == TG_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = tg_fail(&owned_error, "cannot append TelegramBotToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tg_keywords[] = {"telegram", "tgram"};
static const char *const tg_prefix[] = {"telegram", "tgram://"};
static br_detector tg_detector = {
    .type = 91, .version = 0, .name = "TelegramBotToken", .custom_name = "",
    .description = "Telegram Bot API tokens are used to authenticate requests to the Telegram Bot API. They can be used to control and interact with Telegram bots.",
    .keywords = tg_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tg_scan,
};

int br_telegrambottoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tg_fail(error, "invalid TelegramBotToken detector output");
    *out = NULL;
    if (!tg_detector.state &&
        br_regex_compile_prefixed(tg_prefix, 2, "\\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\\b",
                                  (br_regex **)&tg_detector.state, error) != 0)
        return -1;
    *out = &tg_detector;
    return 0;
}
