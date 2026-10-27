/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/deno/denodeploy.go. */
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

typedef struct { br_json *login; char *cause; } denodeploy_user;

static int denodeploy_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int denodeploy_login(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    denodeploy_user *response = user;
    if (!br_json_field_name(name, "login") || !value) return 0; /* null string is a no-op. */
    if (!json_object_is_type(value, json_type_string)) {
        /* First known type error sticks even if a later member overwrites login. */
        if (!response->cause && br_json_type_cause(value, "userResponse.login", "string", &response->cause) != 0)
            return -1;
        return 0;
    }
    json_object_put(response->login);
    response->login = json_object_get(value); /* Ordered visitors lend their values. */
    return 0;
}

/* 0 is typed success (including root null/{}), +1 an owned ordinary decode
 * cause, and -1 an owned resource/unsupported scan failure, never verification. */
static int denodeploy_decode(br_slice body, br_json **login, char **cause, char **error)
{
    *login = NULL;
    *cause = NULL;
    /* Only the successful ReadAll/whole-Unmarshal response is guarded, never
     * source extraction, read failures or ignored status bodies. Go's invalid
     * UTF-8 replacement and complete Unicode/unquoting/diagnostic parity are
     * not supplied by json-c: fail explicitly rather than rewrite broad bytes. */
    if (!br_utf8_valid(body))
        return denodeploy_fail(error, "unsupported: DenoDeploy invalid UTF-8 JSON response or diagnostic");
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (rc != 0) {
        json_object_put(root);
        return rc < 0 ? denodeploy_fail(error, "cannot decode DenoDeploy response") : 1;
    }
    denodeploy_user response = {0};
    if (root && !json_object_is_type(root, json_type_object)) {
        if (br_json_type_cause(root, NULL, "denodeploy.userResponse", &response.cause) != 0) rc = -1;
    } else if (root) rc = br_json_each_member(body, denodeploy_login, &response);
    json_object_put(root);
    if (rc != 0) {
        json_object_put(response.login);
        free(response.cause);
        return denodeploy_fail(error, "cannot project DenoDeploy response");
    }
    if (response.cause) {
        json_object_put(response.login);
        *cause = response.cause;
        return 1;
    }
    *login = response.login;
    /* Unknown huge numbers are ignored; this is not a float64-map conversion.
     * A NULL login reference represents the successful zero-value string. */
    return 0;
}

static int denodeploy_metadata(br_result *result, br_json *login)
{
    br_slice text = br_json_text(login);
    if (text.len > INT_MAX) return -1;
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "login", value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int denodeploy_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    /* Source dereferences req.Header BEFORE checking NewRequestWithContext's
     * error. Nil context therefore panics; it is not a skip or false finding.
     * The caller has already created the finding before this explicit failure. */
    if (!ctx)
        return denodeploy_fail(error, "unsupported upstream panic: DenoDeploy nil request before Header.Set");
    char authorization[7 + 40 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.deno.com/user",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *decode_cause = NULL;
    const char *cause = NULL;
    char status_cause[96];
    br_json *login = NULL;
    int rc = 0;
    /* All mixed shared setup/allocation/Do failures follow the ordinary retained
     * transport-error policy, without classifying stages by diagnostic text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status == 200) {
        result->verified = true; /* Read/decode failures never undo this decision. */
        if (response.body_error != NULL) cause = response.body_error; /* Empty errors still count. */
        else {
            int decoded = denodeploy_decode(response.body, &login, &decode_cause, error);
            if (decoded < 0) rc = -1;
            else if (decoded != 0) cause = decode_cause;
            else if (denodeploy_metadata(result, login) != 0)
                rc = denodeploy_fail(error, "cannot store DenoDeploy login metadata");
        }
    } else if (response.status != 401) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = denodeploy_fail(error, "cannot format DenoDeploy status cause");
        else cause = status_cause;
    }
    /* body_error is BORROWED. Copy and token-only sanitize every cause BEFORE
     * releasing the response; even a positive +1 setter failure is fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = denodeploy_fail(error, "cannot sanitize DenoDeploy verification error");
    /* Source scan-defers Close only after Do succeeds, reading only on 200.
     * Eager buffering/release, full native client/private-client override,
     * Reader/ABI diagnostics, panic recovery and global parity remain partial. */
    br_http_release(ctx, &response);
    json_object_put(login);
    free(decode_cause);
    free(transport_error);
    return rc;
}

static int denodeploy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return denodeploy_fail(error, "invalid or uninitialized DenoDeploy scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = denodeploy_fail(&owned_error, "cannot create DenoDeploy result");
        /* Finding resources precede the known constructor/Header.Set panic. */
        if (rc == 0 && verify) rc = denodeploy_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = denodeploy_fail(&owned_error, "cannot append DenoDeploy result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const denodeploy_keywords[] = {"ddp_", "ddw_"};
static br_detector denodeploy_detector = {
    .type = 954, .version = 0, .name = "DenoDeploy", .custom_name = "",
    .description = "DenoDeploy is a cloud service for deploying JavaScript and TypeScript applications. DenoDeploy tokens can be used to access and manage these deployments.",
    .keywords = denodeploy_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = denodeploy_scan,
};

int br_denodeploy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return denodeploy_fail(error, "invalid DenoDeploy detector output");
    *out = NULL;
    if (!denodeploy_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(dd[pw]_[a-zA-Z0-9]{36})\\b", &pattern, error) != 0) return -1;
        denodeploy_detector.state = pattern;
    }
    *out = &denodeploy_detector;
    return 0;
}
