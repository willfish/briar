/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/slack/slack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

static int add_extra_len(br_json *extra, const char *key, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *owned = json_object_new_string_len(value ? value : "", (int)len);
    if (!owned || json_object_object_add(extra, key, owned) != 0) {
        json_object_put(owned);
        return -1;
    }
    return 0;
}

static int add_extra(br_json *extra, const char *key, const char *value)
{
    return add_extra_len(extra, key, value, value ? strlen(value) : 0);
}

typedef struct {
    bool ok;
    char *error_field, *url, *team, *user, *team_id, *user_id, *bot_id, *cause;
    size_t error_len, url_len, team_len, user_len, team_id_len, user_id_len, bot_id_len;
    bool ordinary, fatal;
} slack_auth;

static void slack_auth_clear(slack_auth *auth)
{
    free(auth->error_field); free(auth->url); free(auth->team); free(auth->user);
    free(auth->team_id); free(auth->user_id); free(auth->bot_id); free(auth->cause);
    *auth = (slack_auth){0};
}

static int slack_type(slack_auth *auth, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!auth->ordinary) {
        auth->ordinary = true;
        auth->cause = next;
    } else free(next);
    return 0;
}

static int slack_string(slack_auth *auth, br_json *value, char **slot, size_t *len, const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) return slack_type(auth, value, field, "string");
    br_slice text = br_json_text(value);
    if (text.len == SIZE_MAX) return -1;
    char *owned = malloc(text.len + 1);
    if (!owned) return -1;
    if (text.len) memcpy(owned, text.data, text.len);
    owned[text.len] = '\0';
    free(*slot);
    *slot = owned;
    *len = text.len;
    return 0;
}

static bool slack_eq(const char *text, size_t len, const char *literal)
{
    size_t n = strlen(literal);
    return text && len == n && !memcmp(text, literal, n);
}

static int slack_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    slack_auth *auth = user;
    int rc = 0;
    if (br_json_field_name(name, "ok")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_boolean)) return slack_type(auth, value, "authRes.ok", "bool");
        auth->ok = json_object_get_boolean(value);
        return 0;
    }
    if (br_json_field_name(name, "error")) rc = slack_string(auth, value, &auth->error_field, &auth->error_len, "authRes.error");
    else if (br_json_field_name(name, "url")) rc = slack_string(auth, value, &auth->url, &auth->url_len, "authRes.url");
    else if (br_json_field_name(name, "team")) rc = slack_string(auth, value, &auth->team, &auth->team_len, "authRes.team");
    else if (br_json_field_name(name, "user")) rc = slack_string(auth, value, &auth->user, &auth->user_len, "authRes.user");
    else if (br_json_field_name(name, "team_id")) rc = slack_string(auth, value, &auth->team_id, &auth->team_id_len, "authRes.team_id");
    else if (br_json_field_name(name, "user_id")) rc = slack_string(auth, value, &auth->user_id, &auth->user_id_len, "authRes.user_id");
    else if (br_json_field_name(name, "bot_id")) rc = slack_string(auth, value, &auth->bot_id, &auth->bot_id_len, "authRes.bot_id");
    else rc = 0;
    return rc;
}

static int slack_decode(br_slice body, const char *read_error, slack_auth *auth, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &auth->cause);
    if (rc < 0 || rc > 1) { json_object_put(root); free(auth->cause); auth->cause = NULL; return fail(error, "cannot decode Slack response"); }
    if (rc == 1) {
        json_object_put(root);
        auth->ordinary = true;
        return 1;
    }
    br_slice document = {body.data, end};
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return fail(error, "unsupported: Slack invalid UTF-8 in consumed JSON document");
    }
    if (root && !json_object_is_type(root, json_type_null) && !json_object_is_type(root, json_type_object))
        rc = slack_type(auth, root, NULL, "slack.authRes");
    else if (root && json_object_is_type(root, json_type_object))
        rc = br_json_each_member(document, slack_member, auth);
    json_object_put(root);
    if (rc != 0 || auth->fatal) return fail(error, "cannot project Slack response");
    return auth->ordinary ? 1 : 0;
}

static int unexpected_auth(const slack_auth *auth, char **out)
{
    static const char prefix[] = "unexpected error auth response ";
    if (auth->error_len > SIZE_MAX - sizeof(prefix)) return -1;
    size_t n = sizeof(prefix) - 1 + auth->error_len;
    char *message = malloc(n + 1);
    if (!message) return -1;
    memcpy(message, prefix, sizeof(prefix) - 1);
    if (auth->error_len && auth->error_field)
        memcpy(message + sizeof(prefix) - 1, auth->error_field, auth->error_len);
    message[n] = '\0';
    *out = message;
    return 0;
}

static int verify_slack(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx) return 1;
    if (token.len > SIZE_MAX - 8) return fail(error, "Slack authorization is too large");
    char *authz = malloc(7 + token.len + 1);
    if (!authz) return fail(error, "cannot format Slack authorization");
    memcpy(authz, "Bearer ", 7);
    memcpy(authz + 7, token.data, token.len);
    authz[7 + token.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json; charset=utf-8"},
        {"Authorization", authz},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://slack.com/api/auth.test",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 13,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char *unexpected = NULL;
    const char *cause = NULL;
    bool error_present = false;
    slack_auth auth = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        error_present = true;
        cause = send_error;
    } else {
        int decoded = slack_decode(response.body, response.body_error, &auth, error);
        if (decoded < 0) rc = -1;
        else {
            if (decoded > 0) {
                error_present = true;
                cause = auth.cause;
            }
            if (auth.ok) {
                result->verified = true;
                if (add_extra_len(result->extra_data, "team", auth.team, auth.team_len) != 0 ||
                    add_extra_len(result->extra_data, "name", auth.user, auth.user_len) != 0)
                    rc = fail(error, "cannot store Slack identity");
            } else if (!slack_eq(auth.error_field, auth.error_len, "invalid_auth") &&
                       !slack_eq(auth.error_field, auth.error_len, "account_inactive") &&
                       !slack_eq(auth.error_field, auth.error_len, "token_revoked")) {
                if (unexpected_auth(&auth, &unexpected) != 0)
                    rc = fail(error, "cannot format Slack auth error");
                else {
                    error_present = true;
                    cause = unexpected;
                }
            }
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = -1;
    slack_auth_clear(&auth);
    free(unexpected);
    free(send_error);
    free(authz);
    return rc;
}

typedef struct { br_regex *bot, *user, *access, *refresh; } slack_state;

static int scan_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_regex *pattern, const char *token_type, br_slice input,
                    br_results *out, char **owned)
{
    br_captures tokens = {0};
    int rc = br_captures_find(pattern, input, &tokens, false, owned);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        if (verify && !ctx) continue;
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = fail(owned, "cannot create Slack finding");
        if (!rc) {
            result.extra_data = json_object_new_object();
            if (!result.extra_data ||
                add_extra(result.extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/slack/") != 0 ||
                add_extra(result.extra_data, "token_type", token_type) != 0)
                rc = fail(owned, "cannot store Slack metadata");
        }
        if (!rc && verify && verify_slack(ctx, token, &result, owned) != 0) rc = -1;
        if (!rc && br_results_push(out, &result) != 0) rc = fail(owned, "cannot append Slack finding");
        br_result_clear(&result);
    }
    br_captures_clear(&tokens);
    return rc;
}

static int scan_slack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    slack_state *state = detector ? (slack_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Slack scan");
    size_t before = out->len;
    char *owned = NULL;
    int rc = scan_one(detector, ctx, verify, state->bot, "Slack Bot Token", input, out, &owned);
    if (!rc) rc = scan_one(detector, ctx, verify, state->user, "Slack User Token", input, out, &owned);
    if (!rc) rc = scan_one(detector, ctx, verify, state->access, "Slack Workspace Access Token", input, out, &owned);
    if (!rc) rc = scan_one(detector, ctx, verify, state->refresh, "Slack Workspace Refresh Token", input, out, &owned);
    if (rc) rollback(out, before);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"xoxb-", "xoxp-", "xoxa-", "xoxr-"};
static br_detector slack = {
    .type = 13, .version = 0, .name = "Slack", .custom_name = "",
    .description = "Slack tokens can be used to authenticate API requests to the Slack platform, allowing access to various workspace resources and functionalities.",
    .keywords = keywords, .nkeywords = 4,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_slack,
};

int br_slack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Slack detector output");
    *out = NULL;
    if (slack.state) { *out = &slack; return 0; }
    slack_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Slack patterns");
    if (br_regex_compile("(xoxb\\-[0-9]{10,13}\\-[0-9]{10,13}[a-zA-Z0-9\\-]*)", &state->bot, error) != 0 ||
        br_regex_compile("(xoxp\\-[0-9]{10,13}\\-[0-9]{10,13}[a-zA-Z0-9\\-]*)", &state->user, error) != 0 ||
        br_regex_compile("(xoxa\\-[0-9]{10,13}\\-[0-9]{10,13}[a-zA-Z0-9\\-]*)", &state->access, error) != 0 ||
        br_regex_compile("(xoxr\\-[0-9]{10,13}\\-[0-9]{10,13}[a-zA-Z0-9\\-]*)", &state->refresh, error) != 0) {
        free(state);
        return -1;
    }
    slack.state = state;
    *out = &slack;
    return 0;
}
