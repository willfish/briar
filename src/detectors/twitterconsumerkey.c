/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twitterconsumerkey/twitterconsumerkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int twitter_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int twitter_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return twitter_fail(error, "cannot store TwitterConsumerkey verification error");
    return 0;
}

typedef struct {
    char *token;
    size_t token_len;
    bool has_token, failed;
    char *cause;
} twitter_token;

static void twitter_keep(twitter_token *fields, char *cause)
{
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = cause;
    } else free(cause);
}

/* 0 is a completed diagnostic, even when cause is NULL. Every other code is fatal. */
__attribute__((weak)) int br_twitterconsumerkey_type_cause(br_json *value, const char *field,
                                                           char **cause)
{
    return br_json_type_cause(value, field, "string", cause);
}

static int twitter_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    twitter_token *fields = user;
    const char *field = NULL;
    if (br_json_field_name(name, "token_type")) field = "tokenResponse.TokenType";
    else if (br_json_field_name(name, "access_token")) field = "tokenResponse.AccessToken";
    else return 0;
    if (value && !json_object_is_type(value, json_type_null) &&
        !json_object_is_type(value, json_type_string)) {
        char *cause = NULL;
        int typed = br_twitterconsumerkey_type_cause(value, field, &cause);
        if (typed != 0) {
            free(cause);
            return typed;
        }
        twitter_keep(fields, cause);
        return 0;
    }
    if (!br_json_field_name(name, "access_token")) return 0;
    /* Null into a string preserves the previous token, including its length. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(fields->token);
    fields->token = copy;
    fields->token_len = text.len;
    fields->has_token = true;
    return 0;
}

__attribute__((weak)) int br_twitterconsumerkey_json_document(br_slice body, const char *read_error,
                                                               br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_twitterconsumerkey_each_member(br_slice object, br_json_member_fn callback,
                                                            void *user)
{
    return br_json_each_member(object, callback, user);
}

static int twitter_access_token(br_slice body, const char *read_error, char **token,
                                 size_t *token_len, char **cause)
{
    twitter_token fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int parsed = br_twitterconsumerkey_json_document(body, read_error, &root, &end, &fields.cause);
    int visit = 0;
    if (parsed == 0 && root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            char *typed = NULL;
            if (br_json_type_cause(root, NULL, "twitterconsumerkey.tokenResponse", &typed) != 0)
                visit = -1;
            else twitter_keep(&fields, typed);
        } else visit = br_twitterconsumerkey_each_member((br_slice){body.data, end}, twitter_member, &fields);
    }
    int rc = 0;
    *token = NULL;
    *token_len = 0;
    if ((parsed != 0 && parsed != 1) || visit != 0) rc = -1;
    else if (parsed == 1 || fields.failed) rc = 1;
    else if (fields.has_token) {
        *token = fields.token;
        *token_len = fields.token_len;
        fields.token = NULL;
    }
    json_object_put(root);
    free(fields.token);
    if (rc < 0) free(fields.cause);
    else *cause = fields.cause;
    return rc < 0 ? -1 : rc;
}

static int twitter_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret, br_result *result,
                          char **error)
{
    static const char body[] = "grant_type=client_credentials";
    /* Payload exists before the constructor. Nil context fails before Basic. */
    if (!ctx) return twitter_cause(result, "net/http: nil Context", key, error);
    char *authorization = NULL;
    int rc = br_http_basic_auth(key, secret, &authorization, error);
    if (rc != 0) return rc;
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/x-www-form-urlencoded;charset=UTF-8"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.twitter.com/oauth2/token",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status[64];
    char *cause = NULL;
    char *token = NULL;
    size_t token_len = 0;
    bool failed = false;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        failed = true;
        cause = send_error;
    } else if (response.status != 200) {
        failed = true;
        snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
        cause = strdup(status);
        if (!cause) rc = twitter_fail(error, "cannot store TwitterConsumerkey status");
    } else {
        char *decode = NULL;
        int decoded = twitter_access_token(response.body, response.body_error, &token, &token_len,
                                           &decode);
        if (decoded < 0) rc = twitter_fail(error, "cannot decode TwitterConsumerkey token");
        else if (decoded > 0) {
            failed = true;
            cause = decode;
        }
        if (cause != decode) free(decode);
    }
    br_http_release(ctx, &response);
    if (cause != send_error) free(send_error);
    free(authorization);
    if (rc == 0 && !failed && token) {
        if (memchr(token, '\0', token_len)) {
            /* A C-string header would silently send only the prefix. */
            failed = true;
            cause = strdup("unsupported: Twitter access token contains NUL");
            if (!cause) rc = twitter_fail(error, "cannot store TwitterConsumerkey status");
        } else {
        char *bearer = token_len > SIZE_MAX - 8 ? NULL : malloc(7 + token_len + 1);
        if (!bearer) rc = twitter_fail(error, "cannot allocate TwitterConsumerkey bearer");
        else {
            memcpy(bearer, "Bearer ", 7);
            if (token_len) memcpy(bearer + 7, token, token_len);
            bearer[7 + token_len] = '\0';
            const br_header bearer_headers[] = {{"Authorization", bearer}};
            const br_http_request verify_request = {
                .method = "GET", .url = "https://api.twitter.com/2/tweets/20",
                .headers = bearer_headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
            };
            br_http_response verified = {0};
            char *verify_error = NULL;
            if (br_http_send(ctx, &verify_request, &verified, &verify_error) != 0) {
                failed = true;
                cause = verify_error;
            } else if (verified.status == 200 || verified.status == 403) result->verified = true;
            else if (verified.status != 401) {
                failed = true;
                snprintf(status, sizeof(status), "unexpected HTTP response status %d", verified.status);
                cause = strdup(status);
                if (!cause) rc = twitter_fail(error, "cannot store TwitterConsumerkey status");
            }
            br_http_release(ctx, &verified);
            if (cause != verify_error) free(verify_error);
            free(bearer);
        }
        }
    }
    if (rc == 0 && twitter_cause(result, cause, key, error) != 0) rc = -1;
    free(cause);
    free(token);
    return rc;
}

static int twitter_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !out || (!input.data && input.len))
        return twitter_fail(error, "invalid or uninitialized TwitterConsumerkey scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &secrets, true, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice secret = br_captures_at(&secrets, s);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret",
                                      (br_slice){0}) != 0)
                rc = twitter_fail(&owned_error, "cannot create TwitterConsumerkey result");
            else if (verify)
                rc = twitter_verify(ctx, key, secret, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = twitter_fail(&owned_error, "cannot append TwitterConsumerkey result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const twitter_keywords[] = {"twitter"};
static const char *const twitter_key_prefix[] = {"twitter", "consumer", "key"};
static const char *const twitter_secret_prefix[] = {"twitter", "consumer", "secret"};
static br_regex *twitter_patterns[2];
static br_detector twitter_detector = {
    .type = 989, .version = 0, .name = "TwitterConsumerkey", .custom_name = "",
    .description = "Twitter Consumer Keys and Secrets are used to authenticate API requests to Twitter. They allow access to Twitter's API to manage user data and perform actions on behalf of users.",
    .keywords = twitter_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = twitter_scan,
};

int br_twitterconsumerkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return twitter_fail(error, "invalid TwitterConsumerkey detector output");
    *out = NULL;
    if (!twitter_patterns[0] &&
        br_regex_compile_prefixed(twitter_key_prefix, 3, "\\b([a-zA-Z0-9]{25})\\b",
                                  &twitter_patterns[0], error) != 0)
        return -1;
    if (!twitter_patterns[1] &&
        br_regex_compile_prefixed(twitter_secret_prefix, 3, "\\b([a-zA-Z0-9]{50})\\b",
                                  &twitter_patterns[1], error) != 0)
        return -1;
    twitter_detector.state = twitter_patterns;
    *out = &twitter_detector;
    return 0;
}
