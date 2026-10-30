/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/spotifykey, and oauth2 v0.34.0
 * client-credentials auto-detect. The defaults constructor is commented out. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char token_url[] = "https://accounts.spotify.com/api/token";
static const char *const secret_keywords[] = {"key", "secret"};
static const char *const id_keywords[] = {"id"};

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool header_value(const br_http_response *response, const char *name, const char **value)
{
    for (size_t i = 0; i < response->nheaders; ++i) {
        if (!response->headers[i].name || strcasecmp(response->headers[i].name, name)) continue;
        *value = response->headers[i].value ? response->headers[i].value : "";
        return true;
    }
    return false;
}

static bool form_content(const char *value)
{
    while (*value == ' ' || *value == '\t') ++value;
    return !strncasecmp(value, "application/x-www-form-urlencoded", 33) ||
           !strncasecmp(value, "text/plain", 10);
}

static bool query_value(br_slice body, const char *key, char **out, size_t *out_len)
{
    size_t key_len = strlen(key), at = 0;
    while (at < body.len) {
        size_t end = at;
        while (end < body.len && body.data[end] != '&') ++end;
        if (end - at > key_len && !memcmp(body.data + at, key, key_len) && body.data[at + key_len] == '=') {
            size_t n = end - (at + key_len + 1);
            char *copy = malloc(n + 1);
            if (!copy) return false;
            memcpy(copy, body.data + at + key_len + 1, n);
            copy[n] = '\0';
            free(*out);
            *out = copy;
            *out_len = n;
        }
        at = end < body.len ? end + 1 : end;
    }
    return true;
}

typedef struct {
    char *data;
    size_t len;
} spotify_text;

typedef struct {
    spotify_text access, type, error_code;
    int rc;
} spotify_token;

static int copy_token_text(br_json *value, spotify_text *slot)
{
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->data);
    slot->data = copy;
    slot->len = text.len;
    return 0;
}

static int token_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    spotify_token *token = user;
    spotify_text *slot = NULL;
    if (br_json_field_name(name, "access_token")) slot = &token->access;
    else if (br_json_field_name(name, "token_type")) slot = &token->type;
    else if (br_json_field_name(name, "error")) slot = &token->error_code;
    else return 0;
    enum json_type kind = json_object_get_type(value);
    /* encoding/json ignores null for a string, so a prior token field stays. */
    if (kind == json_type_null) return 0;
    if (kind != json_type_string) {
        if (!token->rc) token->rc = 1;
        return 0;
    }
    if (copy_token_text(value, slot) != 0) { token->rc = -1; return -1; }
    return 0;
}

/* Token.Type maps an empty type to Bearer. Equality is the full string, not a C prefix. */
static bool bearer_type(const char *type, size_t len)
{
    if (!type || len == 0) return true;
    return len == 6 && !strncasecmp(type, "bearer", 6);
}

/* 0 means this auth style produced a token. 1 means try the other style. */
static int token_style(const br_scan_ctx *ctx, const char *id, const char *secret, bool params,
                       bool *bearer, char **error)
{
    *bearer = false;
    char *body = NULL;
    char *authorization = NULL;
    size_t body_len = 0;
    if (!params) {
        body = strdup("grant_type=client_credentials");
        if (!body) return fail(error, "cannot create Spotify token body");
        body_len = strlen(body);
        if (br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                               (br_slice){(const unsigned char *)secret, strlen(secret)},
                               &authorization, error) != 0) {
            free(body);
            return fail(error, "cannot format Spotify authorization");
        }
    } else {
        size_t need = sizeof("client_id=&client_secret=&grant_type=client_credentials") + strlen(id) + strlen(secret);
        body = malloc(need);
        if (!body) return fail(error, "cannot create Spotify token body");
        body_len = (size_t)sprintf(body, "client_id=%s&client_secret=%s&grant_type=client_credentials", id, secret);
    }
    const br_header headers[2] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", authorization ? authorization : ""},
    };
    const br_http_request request = {
        .method = "POST", .url = token_url, .headers = headers, .nheaders = params ? 1 : 2,
        .body = {(const unsigned char *)body, body_len},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 90,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 1;
    char *access = NULL, *type = NULL, *error_code = NULL;
    size_t access_len = 0, type_len = 0, error_len = 0;
    if (sent == 0) {
        br_slice payload = response.body;
        if (payload.len > (1u << 20)) payload.len = 1u << 20;
        const char *content = NULL;
        bool form = header_value(&response, "Content-Type", &content) && form_content(content);
        bool failed = response.status < 200 || response.status > 299;
        if (form) {
            if (!query_value(payload, "access_token", &access, &access_len) ||
                !query_value(payload, "token_type", &type, &type_len) ||
                !query_value(payload, "error", &error_code, &error_len))
                rc = fail(error, "cannot parse Spotify token response");
            else if (!failed && error_len == 0 && access_len > 0) {
                *bearer = bearer_type(type, type_len);
                rc = 0;
            }
        } else {
            br_json *value = NULL;
            char *cause = NULL;
            size_t end = 0;
            int decoded = br_json_first_document(payload, response.body_error, &value, &end, &cause);
            free(cause);
            if (decoded < 0 || decoded > 1) rc = fail(error, "cannot decode Spotify token response");
            else if (!decoded && value && json_object_get_type(value) == json_type_object) {
                json_object_put(value);
                spotify_token token = {0};
                int walked = br_json_each_member((br_slice){payload.data, end}, token_member, &token);
                if (walked != 0 || token.rc < 0) rc = fail(error, "cannot decode Spotify token response");
                else if (!token.rc && !failed && token.error_code.len == 0 && token.access.len > 0) {
                    *bearer = bearer_type(token.type.data, token.type.len);
                    rc = 0;
                }
                free(token.access.data); free(token.type.data); free(token.error_code.data);
            } else json_object_put(value);
        }
    }
    /* Request body and Authorization stay alive until release. */
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    free(body);
    free(access); free(type); free(error_code);
    return rc;
}

static int verify_spotify(const br_scan_ctx *ctx, const char *secret, const char *id,
                          br_result *result, char **error)
{
    /* Each Config has a fresh auth-style cache, so every pair probes independently. */
    bool bearer = false;
    int rc = token_style(ctx, id, secret, false, &bearer, error);
    if (rc < 0) return -1;
    if (rc > 0) {
        rc = token_style(ctx, id, secret, true, &bearer, error);
        if (rc < 0) return -1;
    }
    if (rc == 0 && bearer) result->verified = true;
    return 0;
}

static int scan_spotify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    /* context.WithValue panics before matching when the parent is nil. */
    if (!ctx) return fail(error, "cannot create context from nil parent");
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SpotifyKey scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures secrets = {0}, ids = {0};
    int rc = br_captures_find(patterns[0], input, &secrets, false, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &ids, false, error);
    for (size_t i = 0; rc == 0 && i < secrets.len; ++i) {
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&secrets, i), "key") != 0)
                rc = fail(error, "out of memory creating SpotifyKey result");
            else if (verify && verify_spotify(ctx, secrets.items[i], ids.items[j], &result, error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append SpotifyKey result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&ids);
    return rc == 0 ? 0 : -1;
}

static const char *const spotify_keywords[] = {"spotify"};
static br_regex *spotify_patterns[2];
static br_detector spotify_detector = {
    .type = 90, .version = 0, .name = "SpotifyKey", .custom_name = "",
    .description = "Spotify API keys can be used to access and modify data within Spotify's services.",
    .keywords = spotify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = spotify_patterns, .scan = scan_spotify,
};

int br_spotifykey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SpotifyKey detector output");
    *out = NULL;
    if (!spotify_patterns[0] &&
        br_regex_compile_prefixed(secret_keywords, 2, "\\b([A-Za-z0-9]{32})\\b", &spotify_patterns[0], error) != 0)
        return -1;
    if (!spotify_patterns[1] &&
        br_regex_compile_prefixed(id_keywords, 1, "\\b([A-Za-z0-9]{32})\\b", &spotify_patterns[1], error) != 0)
        return -1;
    *out = &spotify_detector;
    return 0;
}
