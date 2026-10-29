/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/launchdarkly/launchdarkly.go. */
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

static int launchdarkly_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause, char **error)
{
    /* Zero redaction secrets, including a nil cause. Nil is a checked no-op. */
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return launchdarkly_fail(error, "cannot store LaunchDarkly verification error");
    return 0;
}

/* Caller order: Verified, mandatory zero-secret setter, then ExtraData. The
 * empty NoV object must still be installed when the setter runs. */
static int apply_caller(br_result *result, br_json *pending, bool verified, char *cause,
                        char **error)
{
    result->verified = verified;
    int stored = set_cause(result, cause, error);
    free(cause);
    if (stored != 0) {
        json_object_put(pending);
        return -1;
    }
    json_object_put(result->extra_data);
    result->extra_data = pending;
    return 0;
}

typedef struct {
    char *text[11];
    size_t len[11];
    bool service;
    bool bad;
    char *cause;
} identity;

static void identity_clear(identity *id)
{
    for (size_t i = 0; i < 11; ++i) free(id->text[i]);
    free(id->cause);
    *id = (identity){0};
}

static int copy_text(char **dst, size_t *len, br_slice text)
{
    if (text.len > INT_MAX || (!text.data && text.len)) return -1;
    char *next = malloc(text.len + 1);
    if (!next) return -1;
    if (text.len) memcpy(next, text.data, text.len);
    next[text.len] = '\0';
    free(*dst);
    *dst = next;
    *len = text.len;
    return 0;
}

static int note_type(identity *id, br_json *value, const char *field, const char *expected)
{
    if (id->bad) return 0;
    id->bad = true;
    return br_json_type_cause(value, field, expected, &id->cause) == 0 ? 0 : -1;
}

static int read_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded; /* String and bool fields report number with no lexeme. */
    identity *id = user;
    static const char *const folded[] = {
        "accountid", "environmentid", "projectid", "environmentname", "projectname",
        "authkind", "tokenkind", "clientid", "tokenname", "tokenid", "memberid",
    };
    static const char *const fields[] = {
        "callerIdentity.accountId", "callerIdentity.environmentId", "callerIdentity.projectId",
        "callerIdentity.environmentName", "callerIdentity.projectName", "callerIdentity.authKind",
        "callerIdentity.tokenKind", "callerIdentity.clientId", "callerIdentity.tokenName",
        "callerIdentity.tokenId", "callerIdentity.memberId",
    };
    if (br_json_field_name(name, "servicetoken")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (json_object_is_type(value, json_type_boolean)) {
            id->service = json_object_get_boolean(value); /* Still assigned after a sticky cause. */
            return 0;
        }
        return note_type(id, value, "callerIdentity.serviceToken", "bool");
    }
    for (size_t i = 0; i < 11; ++i) {
        if (!br_json_field_name(name, folded[i])) continue;
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (json_object_is_type(value, json_type_string))
            return copy_text(&id->text[i], &id->len[i], br_json_text(value));
        return note_type(id, value, fields[i], "string");
    }
    return 0; /* Unknown members are ignored. tokenId is copied but never published. */
}

static int put_text(br_json *object, const char *key, const char *text, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text ? text : "", (int)len);
    if (!value) return -1;
    if (json_object_object_add(object, key, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int build_extra(const identity *id, br_json **out, char **error)
{
    br_json *extra = json_object_new_object();
    if (!extra) return launchdarkly_fail(error, "cannot create LaunchDarkly extra data");
    static const char *const keys[] = {
        "type", "account", "environment_id", "project_id", "environment_name", "project_name",
        "auth_kind", "token_kind", "client_id", "token_name", "member_id",
    };
    static const int slots[] = {0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *text = id->text[slots[i]];
        if (put_text(extra, keys[i], text, text ? id->len[slots[i]] : 0) != 0) {
            json_object_put(extra);
            return launchdarkly_fail(error, "cannot create LaunchDarkly extra data");
        }
    }
    /* tokenId is decoded for typing but never published. token_type exists only
     * for the exact tokenKind auth. */
    if (id->len[6] == 4 && id->text[6] && !memcmp(id->text[6], "auth", 4)) {
        const char *kind = id->service ? "service" : "personal";
        if (put_text(extra, "token_type", kind, strlen(kind)) != 0) {
            json_object_put(extra);
            return launchdarkly_fail(error, "cannot create LaunchDarkly extra data");
        }
    }
    *out = extra;
    return 0;
}

/* 0: ordinary outcome. *pending is the uninstalled success map, or NULL when
 * *cause is the ordinary error. -1: resource or visitor failure. Document
 * status 1 is ordinary and is not a visitor status. */
static int decode_identity(const br_http_response *response, br_json **pending, char **cause,
                           char **error)
{
    identity id = {0};
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &id.cause);
    if (rc < 0) {
        json_object_put(root);
        identity_clear(&id);
        return launchdarkly_fail(error, "cannot decode LaunchDarkly response");
    }
    if (rc == 1) {
        *cause = id.cause;
        id.cause = NULL;
        json_object_put(root);
        identity_clear(&id);
        if (!*cause) return launchdarkly_fail(error, "cannot decode LaunchDarkly response");
        return 0;
    }
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            if (br_json_type_cause(root, NULL, "launchdarkly.callerIdentity", &id.cause) != 0)
                rc = -1;
            else id.bad = true;
        } else if (response->body.data && end) {
            int visit = br_json_each_member((br_slice){response->body.data, end}, read_member, &id);
            if (visit != 0) rc = -2; /* Any visitor nonzero is fatal, even after an ordinary cause. */
        }
    }
    json_object_put(root);
    if (rc < 0) {
        identity_clear(&id);
        return launchdarkly_fail(error, rc == -2 ? "cannot visit LaunchDarkly response"
                                                 : "cannot decode LaunchDarkly response");
    }
    if (id.bad || id.cause) {
        if (!id.cause) {
            identity_clear(&id);
            return launchdarkly_fail(error, "cannot decode LaunchDarkly response");
        }
        *cause = id.cause;
        id.cause = NULL;
        identity_clear(&id);
        return 0;
    }
    rc = build_extra(&id, pending, error);
    identity_clear(&id);
    return rc;
}

static int launchdarkly_verify(const br_scan_ctx *ctx, const char *key, int32_t type,
                                br_json **pending, bool *verified, char **cause, char **error)
{
    *pending = NULL;
    *verified = false;
    *cause = NULL;
    /* Nil context fails construction. Do not send or release; the caller still applies. */
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        return *cause ? 0 : launchdarkly_fail(error, "cannot store LaunchDarkly verification error");
    }
    const br_header headers[] = {{"Authorization", key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://app.launchdarkly.com/api/v2/caller-identity",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    if (send_rc != 0) {
        *cause = transport_error;
        br_http_release(ctx, &response);
        return 0;
    }
    free(transport_error);
    if (response.status == 200) {
        int decoded = decode_identity(&response, pending, cause, error);
        br_http_release(ctx, &response);
        if (decoded != 0) {
            json_object_put(*pending);
            free(*cause);
            *pending = NULL;
            *cause = NULL;
            return -1;
        }
        *verified = *pending && !*cause;
        return 0;
    }
    if (response.status == 401) {
        br_http_release(ctx, &response);
        return 0;
    }
    char status_error[64];
    int formatted = snprintf(status_error, sizeof(status_error), "unexpected status code: %d",
                             response.status);
    if (formatted < 0 || (size_t)formatted >= sizeof(status_error)) {
        br_http_release(ctx, &response);
        return launchdarkly_fail(error, "cannot format LaunchDarkly status");
    }
    *cause = strdup(status_error);
    if (!*cause) {
        br_http_release(ctx, &response);
        return launchdarkly_fail(error, "cannot format LaunchDarkly status");
    }
    br_http_release(ctx, &response);
    return 0;
}

static int launchdarkly_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return launchdarkly_fail(error, "invalid or uninitialized LaunchDarkly scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Unprefixed grammar. unique=false keeps duplicates in source order.
     * TrimSpace is a no-op for this alphabet. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = launchdarkly_fail(&owned_error, "cannot create LaunchDarkly result");
        else {
            result.extra_data = json_object_new_object();
            if (!result.extra_data)
                rc = launchdarkly_fail(&owned_error, "cannot create LaunchDarkly extra data");
            else if (verify) {
                br_json *pending = NULL;
                bool verified = false;
                char *cause = NULL;
                if (launchdarkly_verify(ctx, keys.items[i], detector->type, &pending, &verified,
                                        &cause, &owned_error) != 0 ||
                    apply_caller(&result, pending, verified, cause, &owned_error) != 0)
                    rc = -1;
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = launchdarkly_fail(&owned_error, "cannot append LaunchDarkly result");
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

static const char *const launchdarkly_keywords[] = {"api-", "sdk-"};
static br_detector launchdarkly_detector = {
    .type = 191,
    .version = 0,
    .name = "LaunchDarkly",
    .custom_name = "",
    .description = "LaunchDarkly is a feature management platform that allows teams to control the visibility of features to users. LaunchDarkly API keys can be used to access and modify feature flags and other resources within a LaunchDarkly account.",
    .keywords = launchdarkly_keywords,
    .nkeywords = 2,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = launchdarkly_scan,
};

int br_launchdarkly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return launchdarkly_fail(error, "invalid LaunchDarkly detector output");
    *out = NULL;
    if (!launchdarkly_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
                             &regex, error) != 0)
            return -1;
        launchdarkly_detector.state = regex;
    }
    *out = &launchdarkly_detector;
    return 0;
}
