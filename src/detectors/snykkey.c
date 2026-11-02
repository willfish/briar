/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/snykkey/snykkey.go. */
#include "detectors.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    size_t len;
} snyk_org_slot;

typedef struct {
    char *username, *email;
    size_t username_len, email_len;
    snyk_org_slot *orgs;
    size_t norgs, cap, org_at;
    char *cause;
    bool failed;
} snyk_user;

static void snyk_user_clear(snyk_user *user)
{
    free(user->username);
    free(user->email);
    for (size_t i = 0; i < user->cap; ++i) free(user->orgs[i].name);
    free(user->orgs);
    free(user->cause);
}

static int snyk_store(char **slot, size_t *len, br_slice text)
{
    if (text.len == SIZE_MAX) return -1;
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len && text.data) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*slot);
    *slot = copy;
    *len = text.len;
    return 0;
}

/* JSON null leaves a Go string unchanged. It is not a type error. */
static int snyk_take(br_json *value, char **slot, size_t *len)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    return snyk_store(slot, len, br_json_text(value));
}

static void snyk_discard_orgs(snyk_user *user)
{
    for (size_t i = 0; i < user->cap; ++i) free(user->orgs[i].name);
    free(user->orgs);
    user->orgs = NULL;
    user->norgs = 0;
    user->cap = 0;
}

static int snyk_grow_orgs(snyk_user *user, size_t n)
{
    if (n <= user->cap) return 0;
    if (n > SIZE_MAX / sizeof(*user->orgs)) return -1;
    snyk_org_slot *orgs = realloc(user->orgs, n * sizeof(*orgs));
    if (!orgs) return -1;
    memset(orgs + user->cap, 0, (n - user->cap) * sizeof(*orgs));
    user->orgs = orgs;
    user->cap = n;
    return 0;
}

static int snyk_note_type(snyk_user *fields, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    if (br_json_type_cause(value, field, expected, &next) != 0) return -1;
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = next;
    } else free(next);
    return 0;
}

static int snyk_org_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    snyk_user *fields = user;
    snyk_org_slot *org = &fields->orgs[fields->org_at];
    if (!br_json_field_name(name, "name")) return 0;
    if (value && !json_object_is_type(value, json_type_string) &&
        !json_object_is_type(value, json_type_null))
        return snyk_note_type(fields, value, "organization.orgs.name", "string");
    return snyk_take(value, &org->name, &org->len);
}

static int snyk_org(void *user, size_t index, br_json *value, br_slice encoded)
{
    snyk_user *fields = user;
    fields->org_at = index;
    /* Null into a struct is ignored, so a reused slot keeps its name. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return snyk_note_type(fields, value, "userDetailsResponse.orgs", "snykkey.organization");
    return br_json_each_member(encoded, snyk_org_member, fields);
}

static int snyk_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    snyk_user *fields = user;
    if (br_json_field_name(name, "username")) {
        if (value && !json_object_is_type(value, json_type_string) &&
            !json_object_is_type(value, json_type_null))
            return snyk_note_type(fields, value, "userDetailsResponse.username", "string");
        return snyk_take(value, &fields->username, &fields->username_len);
    }
    if (br_json_field_name(name, "email")) {
        if (value && !json_object_is_type(value, json_type_string) &&
            !json_object_is_type(value, json_type_null))
            return snyk_note_type(fields, value, "userDetailsResponse.email", "string");
        return snyk_take(value, &fields->email, &fields->email_len);
    }
    if (!br_json_field_name(name, "orgs")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        snyk_discard_orgs(fields);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array))
        return snyk_note_type(fields, value, "userDetailsResponse.orgs", "[]snykkey.organization");
    size_t n = json_object_array_length(value);
    /* An empty array replaces the slice, including its backing array. */
    if (!n) {
        snyk_discard_orgs(fields);
        return 0;
    }
    if (snyk_grow_orgs(fields, n) != 0) return -1;
    int rc = br_json_each_element(encoded, snyk_org, fields);
    if (rc) return rc;
    fields->norgs = n;
    return 0;
}

static int snyk_extra(snyk_user *user, br_result *result)
{
    br_json *extra = json_object_new_object();
    br_json *username = json_object_new_string_len(user->username ? user->username : "", user->username_len);
    br_json *email = json_object_new_string_len(user->email ? user->email : "", user->email_len);
    if (!extra || !username || !email) {
        json_object_put(username);
        json_object_put(email);
        json_object_put(extra);
        return -1;
    }
    if (json_object_object_add(extra, "Username", username) != 0) {
        json_object_put(username);
        json_object_put(email);
        json_object_put(extra);
        return -1;
    }
    if (json_object_object_add(extra, "Email", email) != 0) {
        json_object_put(email);
        json_object_put(extra);
        return -1;
    }
    if (user->norgs) {
        size_t total = user->norgs - 1;
        for (size_t i = 0; i < user->norgs; ++i) {
            if (total == SIZE_MAX || user->orgs[i].len > SIZE_MAX - total - 1) {
                json_object_put(extra);
                return -1;
            }
            total += user->orgs[i].len;
        }
        char *joined = malloc(total + 1);
        if (!joined) {
            json_object_put(extra);
            return -1;
        }
        size_t at = 0;
        for (size_t i = 0; i < user->norgs; ++i) {
            if (i) joined[at++] = ',';
            if (user->orgs[i].len && user->orgs[i].name) memcpy(joined + at, user->orgs[i].name, user->orgs[i].len);
            at += user->orgs[i].len;
        }
        joined[at] = '\0';
        br_json *orgs = json_object_new_string_len(joined, total);
        free(joined);
        if (!orgs || json_object_object_add(extra, "Organizations", orgs) != 0) {
            json_object_put(orgs);
            json_object_put(extra);
            return -1;
        }
    }
    result->extra_data = extra;
    return 0;
}

static int snyk_decode(const br_http_response *response, br_result *result, char **cause)
{
    snyk_user user = {0};
    br_json *root = NULL;
    size_t end = 0;
    int decoded = br_json_first_document(response->body, response->body_error, &root, &end, &user.cause);
    /* Only exact document status +1 is an ordinary decode error. Null is success. */
    if (decoded == 1) {
        user.failed = true;
        *cause = user.cause;
        user.cause = NULL;
        snyk_user_clear(&user);
        json_object_put(root);
        result->verified = true;
        return 0;
    }
    if (decoded != 0) {
        snyk_user_clear(&user);
        json_object_put(root);
        return -1;
    }
    int rc = 0;
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            char *next = NULL;
            if (br_json_type_cause(root, NULL, "snykkey.userDetailsResponse", &next) != 0) rc = -1;
            else if (!user.failed) {
                user.failed = true;
                user.cause = next;
            } else free(next);
        } else {
            int visit = br_json_each_member((br_slice){response->body.data, end}, snyk_member, &user);
            if (visit != 0) rc = -1; /* Visitor +1 stays fatal after a saved ordinary cause. */
        }
    }
    if (rc != 0) {
        snyk_user_clear(&user);
        json_object_put(root);
        return -1;
    }
    if (user.failed) {
        *cause = user.cause;
        user.cause = NULL;
        snyk_user_clear(&user);
        json_object_put(root);
        result->verified = true; /* A decode error still counts as verified. */
        return 0;
    }
    if (!user.username_len) {
        *cause = strdup("failed to decode JSON response");
        snyk_user_clear(&user);
        json_object_put(root);
        return *cause ? 0 : -1;
    }
    rc = snyk_extra(&user, result);
    snyk_user_clear(&user);
    json_object_put(root);
    if (rc != 0) return -1;
    result->verified = true;
    return 0;
}

static int snyk_set(br_result *result, const char *cause, const char *token)
{
    br_slice secret = {(const unsigned char *)token, strlen(token)};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int snyk_verify(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    if (!ctx) return snyk_set(result, "net/http: nil Context", token);
    char authorization[48];
    int n = snprintf(authorization, sizeof(authorization), "token %s", token);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://snyk.io/api/v1/user/me",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *decode_cause = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) {
        rc = snyk_decode(&response, result, &decode_cause);
        cause = decode_cause;
    } else if (response.status != 401) {
        int wrote = snprintf(status_error, sizeof(status_error),
                             "unexpected HTTP response status %d", response.status);
        if (wrote < 0 || (size_t)wrote >= sizeof(status_error)) rc = -1;
        else cause = status_error;
    }
    if (rc == 0) rc = snyk_set(result, cause, token);
    br_http_release(ctx, &response);
    free(transport_error);
    free(decode_cause);
    return rc;
}

static int snyk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", snyk_verify, error);
}

static const char *const snyk_keywords[] = {"snyk"};
static br_detector snyk_detector = {
    .type = 89, .version = 0, .name = "SnykKey", .custom_name = "",
    .description = "Snyk is a developer security platform that helps developers find and fix vulnerabilities in their code. Snyk API keys can be used to access and manage Snyk services.",
    .keywords = snyk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = snyk_scan,
};

int br_snykkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid SnykKey detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&snyk_detector,
                            "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
                            error) != 0)
        return -1;
    *out = &snyk_detector;
    return 0;
}
