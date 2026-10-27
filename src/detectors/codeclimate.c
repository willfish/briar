/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/codeclimate/codeclimate.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef enum { CLIMATE_ABORT = -1, CLIMATE_KEEP = 0, CLIMATE_SKIP = 1 } climate_outcome;
typedef struct { bool id_nonempty; char *cause; } response_fields;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int read_id(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    response_fields *fields = user;
    if (!value || !br_json_field_name(name, "id")) return 0; /* String null is a no-op. */
    if (!json_object_is_type(value, json_type_string))
        return br_json_type_cause(value, "response.data.id", "string", &fields->cause) == 0 ? 1 : -1;
    /* Only nonemptiness is observable; do not retain borrowed ID bytes. A NUL
     * byte or whitespace is nonempty, while the last valid empty string resets. */
    fields->id_nonempty = br_json_text(value).len != 0;
    return 0;
}

static int read_data(void *user, br_slice name, br_json *value, br_slice encoded)
{
    response_fields *fields = user;
    if (!value || !br_json_field_name(name, "data")) return 0; /* VALUE-struct null is also a no-op. */
    if (!json_object_is_type(value, json_type_object)) {
        /* This private cause is set/redacted then discarded. Exact Go reflective
         * spelling of the anonymous struct type is deliberately not claimed. */
        return br_json_type_cause(value, "response.data", "struct", &fields->cause) == 0 ? 1 : -1;
    }
    /* Reuse state across Data objects. Original bytes, not a collapsed DOM,
     * preserve nested duplicates and their type-error order. */
    return br_json_each_member(encoded, read_id, fields);
}

/* 0: successful typed first Decode, +1: owned decode cause, -1: resources.
 * A first known-field type error is not rescued by later valid duplicates. */
static int read_response(br_slice body, const char *read_error, br_result *result, char **cause)
{
    response_fields fields = {0}; br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, read_data, &fields);
        else rc = br_json_type_cause(root, NULL, "codeclimate.response", &fields.cause) == 0 ? 1 : -1;
    }
    if (rc == 0) result->verified = fields.id_nonempty; /* Root null starts/keeps false. */
    json_object_put(root);
    *cause = fields.cause;
    return rc < 0 ? -1 : rc;
}

static climate_outcome verify_codeclimate(const br_scan_ctx *ctx, const char *key,
                                           br_result *result, char **error)
{
    if (!ctx) return CLIMATE_SKIP; /* Source constructor failure continues outer key loop. */
    char authorization[53] = "Token token=";
    memcpy(authorization + 12, key, 41); /* Complete 40-byte capture plus NUL. */
    const br_header headers[] = {{"Accept", "application/vnd.api+json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.codeclimate.com/v1/user",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 844,
    };
    br_http_response response = {0}; char *transport_error = NULL, *json_cause = NULL;
    climate_outcome outcome = CLIMATE_KEEP;
    /* ALL shared setup/allocation + Do failures are suppressed. Non-2xx keeps
     * false/nil and never inspects a body/read error or attempts Decode. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.status >= 200 && response.status < 300) {
        int rc = read_response(response.body, response.body_error, result, &json_cause);
        if (rc < 0) {
            fail(error, "cannot decode Codeclimate response"); outcome = CLIMATE_ABORT;
        } else if (rc != 0) {
            const br_slice secret = {result->raw.data, result->raw.len};
            /* Source sets the key-redacted error THEN drops this candidate.
             * Setter +1 is fatal BEFORE private SKIP; copy before release. */
            if (br_result_set_verification_error(result, json_cause, &secret, 1) != 0) {
                fail(error, "cannot sanitize Codeclimate decode error"); outcome = CLIMATE_ABORT;
            } else outcome = CLIMATE_SKIP;
        }
    }
    /* Source scan-defers Close only. ABI1 eager buffering/release, stream read
     * timing, native client configuration and wider diagnostics remain partial. */
    br_http_release(ctx, &response);
    free(json_cause); free(transport_error);
    return outcome;
}

static int scan_codeclimate(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Codeclimate scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; climate_outcome outcome = CLIMATE_KEEP;
        /* TrimSpace changes nothing in the captured lowercase hex alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create Codeclimate result"); outcome = CLIMATE_ABORT;
        }
        if (outcome == CLIMATE_KEEP && verify) outcome = verify_codeclimate(ctx, keys.items[i], &result, &owned_error);
        if (outcome == CLIMATE_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Codeclimate result"); outcome = CLIMATE_ABORT;
        }
        br_result_clear(&result); /* Normal Decode errors never publish a diagnostic. */
        if (outcome == CLIMATE_ABORT) rc = -1;
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"codeclimate"};
static br_detector codeclimate = {
    .type = 844, .version = 0, .name = "Codeclimate", .custom_name = "",
    .description = "Codeclimate is a tool for automated code review and analysis. Codeclimate tokens can be used to access and manage repositories and their analysis results.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_codeclimate,
};

int br_codeclimate_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Codeclimate detector output");
    *out = NULL;
    if (br_key_pattern_init(&codeclimate, "\\b([a-f0-9]{40})\\b", error) != 0) return -1;
    *out = &codeclimate;
    return 0;
}
