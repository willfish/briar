/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/deepseek/deepseek.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bool available; char *cause; } deepseek_response;

static int deepseek_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int deepseek_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    deepseek_response *fields = user;
    if (!br_json_field_name(name, "is_available") || !value) return 0;
    /* Go bool assignments merge in source order; null is a no-op. Save the
     * FIRST type error without letting a later correct duplicate erase it.
     * Continue projection so subsequent resource failures still abort scans. */
    if (json_object_is_type(value, json_type_boolean)) fields->available = json_object_get_boolean(value);
    else if (!fields->cause &&
             br_json_type_cause(value, "response.is_available", "bool", &fields->cause) != 0) return -1;
    return 0;
}

static int deepseek_decode(br_slice body, const char *read_error, bool *available, char **cause)
{
    deepseek_response fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, deepseek_member, &fields);
        else rc = br_json_type_cause(root, NULL, "deepseek.response", &fields.cause) == 0 ? 1 : -1;
    }
    json_object_put(root);
    if (rc == 0 && fields.cause) rc = 1;
    *cause = fields.cause;
    *available = fields.available;
    /* Decode only the FIRST document, validating/projecting its ORIGINAL spans.
     * Unknown huge numbers are ignored by this typed bool struct: do not run
     * float64-map conversion checks or inspect json-c's collapsed duplicates.
     * Selected JSON/UTF-8/unquoting/Reader/error behavior is not full Go parity. */
    return rc == 0 ? 0 : rc == 1 && fields.cause ? 1 : -1;
}

static int deepseek_metadata(br_result *result, bool available, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return deepseek_fail(error, "cannot create DeepSeek extra data");
    br_json *value = json_object_new_string(available ? "true" : "false");
    if (!value) return deepseek_fail(error, "cannot create DeepSeek is_available metadata");
    if (json_object_object_add(result->extra_data, "is_available", value) != 0) {
        json_object_put(value);
        return deepseek_fail(error, "cannot add DeepSeek is_available metadata");
    }
    result->verified = true; /* Successful decoding verifies EVEN when available is false. */
    return 0;
}

static int deepseek_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    /* Known NewRequestWithContext(nil) failure is RETAINED, not skipped. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return deepseek_fail(error, "cannot set DeepSeek verification error");
        return 0;
    }
    /* Source prepares Authorization AFTER construction. A complete 35-byte
     * token needs exactly 42 header bytes + NUL, borrowed through release. */
    char authorization[43];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json; charset=utf-8"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.deepseek.com/user/balance",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *json_cause = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* ABI1 mixes shared setup/allocation and Do errors. Retain that cause
     * without a diagnostic-stage classifier; own resources still fail scans. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) {
        bool available = false;
        int decoded = deepseek_decode(response.body, response.body_error, &available, &json_cause);
        if (decoded < 0) rc = deepseek_fail(error, "cannot decode DeepSeek verification response");
        else if (decoded == 0) rc = deepseek_metadata(result, available, error);
        cause = json_cause; /* +1 is a normal owned decode cause, NOT resource failure. */
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = deepseek_fail(error, "cannot format DeepSeek verification status");
        else cause = status_error;
    }
    /* Source passes ZERO secret arguments: token echoes must remain unchanged.
     * Copy causes BEFORE response release; setter +1 is a fatal own failure. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = deepseek_fail(error, "cannot set DeepSeek verification error");
    /* Source verifier defers DRAIN + close. ABI1 eagerly buffers/releases;
     * body/runtime resource distinctions, full/private client overrides, Go
     * map order and global engine/output behavior remain partial/unproven. */
    br_http_release(ctx, &response);
    free(send_error);
    free(json_cause);
    return rc == 0 ? 0 : -1;
}

static int deepseek_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return deepseek_fail(error, "invalid or uninitialized DeepSeek scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    /* No TrimSpace, normalization, entropy/filtering or cache. Bytewise unique
     * original tokens; deterministic insertion order is a legal Go map order. */
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0}; br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = deepseek_fail(&owned_error, "cannot create DeepSeek result");
        if (rc == 0 && verify && deepseek_verify(ctx, token, &result, &owned_error) != 0) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = deepseek_fail(&owned_error, "cannot append DeepSeek result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const deepseek_keywords[] = {"deepseek"};
static br_detector deepseek_detector = {
    .type = 1026, .version = 0, .name = "DeepSeek", .custom_name = "",
    .description = "DeepSeek is an artificial intelligence company that develops large language models (LLMs)",
    .keywords = deepseek_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = deepseek_scan,
};

int br_deepseek_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return deepseek_fail(error, "invalid DeepSeek detector output");
    *out = NULL;
    if (br_key_pattern_init(&deepseek_detector, "\\b(sk-[a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &deepseek_detector;
    return 0;
}
