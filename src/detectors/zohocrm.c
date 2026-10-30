/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zohocrm/zohocrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include <json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const zohocrm_keywords[] = {"1000."};
static const char zohocrm_url[] = "https://www.zohoapis.com/crm/v7/Leads?fields=Email&per_page=1";

static int zohocrm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zohocrm_store(br_result *result, const char *cause, br_slice token, char **error)
{
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return zohocrm_fail(error, "cannot set ZohoCRM verification error");
    return 0;
}

static int zohocrm_join_len(char **out, const char *prefix, const char *detail, size_t detail_len)
{
    size_t n = strlen(prefix);
    char *message = malloc(n + detail_len + 1);
    if (!message) return -1;
    memcpy(message, prefix, n);
    if (detail_len && detail) memcpy(message + n, detail, detail_len);
    message[n + detail_len] = '\0';
    *out = message;
    return 0;
}

static int zohocrm_join(char **out, const char *prefix, const char *detail)
{
    return zohocrm_join_len(out, prefix, detail, detail ? strlen(detail) : 0);
}

typedef struct {
    char *code;
    char *cause;
    size_t code_len;
    bool ordinary;
} zohocrm_fields;

static bool zohocrm_code_is(const char *code, size_t len, const char *literal)
{
    size_t n = strlen(literal);
    return code && len == n && !memcmp(code, literal, n);
}

static int zohocrm_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    zohocrm_fields *slot = user;
    if (!br_json_field_name(name, "code")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        char *next = NULL;
        int rc = br_json_type_cause(value, "UnauthorizedResponseBody.code", "string", &next);
        if (rc != 0) { free(next); return rc; }
        if (!slot->ordinary) {
            slot->ordinary = true;
            slot->cause = next;
        } else free(next);
        return 0;
    }
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->code);
    slot->code = copy;
    slot->code_len = text.len;
    return 0;
}

static int zohocrm_code(br_slice body, char **code, size_t *code_len, char **cause)
{
    *code = NULL;
    *code_len = 0;
    bool blank = true;
    for (size_t i = 0; i < body.len; ++i)
        if (body.data[i] != ' ' && body.data[i] != '\t' && body.data[i] != '\r' && body.data[i] != '\n') {
            blank = false;
            break;
        }
    if (blank) return zohocrm_join(cause, "unexpected end of JSON input", NULL) == 0 ? 1 : -1;
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc < 0 || rc > 1) { json_object_put(root); return -1; }
    if (rc == 1) { json_object_put(root); return 1; }
    if (json_object_is_type(root, json_type_null)) { json_object_put(root); return 0; }
    if (!json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, "zohocrm.UnauthorizedResponseBody", cause) == 0 ? 1 : -1;
        json_object_put(root);
        return rc;
    }
    json_object_put(root);
    zohocrm_fields parsed = {0};
    rc = br_json_each_member(body, zohocrm_member, &parsed);
    if (rc != 0) { free(parsed.cause); free(parsed.code); return -1; }
    if (parsed.ordinary) { *cause = parsed.cause; free(parsed.code); return 1; }
    *code = parsed.code;
    *code_len = parsed.code_len;
    return 0;
}

static int zohocrm_verify(const br_scan_ctx *ctx, const char *token, br_result *result, char **error)
{
    char authorization[87];
    memcpy(authorization, "Zoho-oauthtoken ", 16);
    memcpy(authorization + 16, token, 70);
    authorization[86] = '\0';
    br_slice secret = {(const unsigned char *)token, 70};
    if (!ctx) return zohocrm_store(result, "net/http: nil Context", secret, error);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = zohocrm_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    char *cause = NULL;
    int rc = 0;
    /* Do and constructor errors are returned raw, not wrapped. */
    if (send_rc != 0) {
        if (transport_error && !(cause = strdup(transport_error)))
            rc = zohocrm_fail(error, "cannot copy ZohoCRM transport error");
    }
    else if (response.status == 200) result->verified = true;
    else if (response.status == 401) {
        if (response.body_error) {
            if (zohocrm_join(&cause, "failed to read response body: ", response.body_error) != 0) rc = -1;
        } else {
            char *code = NULL;
            size_t code_len = 0;
            int decoded = zohocrm_code(response.body, &code, &code_len, &cause);
            if (decoded < 0) rc = -1;
            else if (decoded > 0) {
                char *wrapped = NULL;
                if (zohocrm_join(&wrapped, "failed to parse JSON response: ", cause) != 0) rc = -1;
                free(cause);
                cause = wrapped;
            } else if (zohocrm_code_is(code, code_len, "OAUTH_SCOPE_MISMATCH")) result->verified = true;
            else if (!zohocrm_code_is(code, code_len, "INVALID_TOKEN")) {
                if (zohocrm_join_len(&cause, "unexpected error code: ", code, code_len) != 0) rc = -1;
            }
            free(code);
        }
    } else {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = zohocrm_fail(error, "cannot format ZohoCRM status");
        else cause = strdup(status_error);
    }
    if (!rc) rc = zohocrm_store(result, cause, secret, error);
    free(cause);
    free(transport_error);
    br_http_release(ctx, &response);
    return rc;
}

static int zohocrm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return zohocrm_fail(error, "invalid or uninitialized ZohoCRM scan");
    size_t original_len = out->len;
    br_captures found = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < found.len; ++i)
        if (br_captures_push(&keys, br_captures_at(&found, i), true, &owned_error) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 70)
            rc = zohocrm_fail(&owned_error, "invalid ZohoCRM capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = zohocrm_fail(&owned_error, "cannot create ZohoCRM result");
        else if (verify)
            rc = zohocrm_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = zohocrm_fail(&owned_error, "cannot append ZohoCRM result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&found);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector zohocrm_detector = {
    .type = 1006, .version = 0, .name = "ZohoCRM", .custom_name = "",
    .description = "Zoho CRM is a platform for managing sales, marketing, and customer support. Zoho CRM API access tokens allow access to these services through their REST API.",
    .keywords = zohocrm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zohocrm_scan,
};

int br_zohocrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zohocrm_fail(error, "invalid ZohoCRM detector output");
    *out = NULL;
    if (!zohocrm_detector.state &&
        br_regex_compile("\\b(1000\\.[a-f0-9]{32}\\.[a-f0-9]{32})\\b",
                         (br_regex **)&zohocrm_detector.state, error) != 0)
        return -1;
    *out = &zohocrm_detector;
    return 0;
}
