/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudsmith/cloudsmith.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SMITH_ABORT = -1, SMITH_KEEP = 0, SMITH_SKIP = 1 } cloudsmith_outcome;
typedef struct { bool authenticated; char *cause; } response_fields;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int read_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    response_fields *fields = user;
    if (!value || !br_json_field_name(name, "authenticated")) return 0;
    if (!json_object_is_type(value, json_type_boolean))
        return br_json_type_cause(value, "response.authenticated", "bool", &fields->cause) == 0 ? 1 : -1;
    fields->authenticated = json_object_get_boolean(value);
    return 0;
}

/* 0: complete typed Decode, +1: owned decode cause, -1: helper/resource failure.
 * Ordered visits preserve duplicates: null is a bool no-op, and a later valid
 * duplicate cannot rescue a previous type error. Unknown numbers stay untyped. */
static int read_response(br_slice body, const char *read_error, br_result *result, char **cause)
{
    response_fields fields = {0}; br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (!rc && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, read_field, &fields);
        else
            rc = br_json_type_cause(root, NULL, "cloudsmith.response", &fields.cause) == 0 ? 1 : -1;
    }
    if (!rc) result->verified = fields.authenticated; /* Successful root null leaves false. */
    json_object_put(root);
    *cause = fields.cause;
    return rc < 0 ? -1 : rc;
}

static cloudsmith_outcome verify_cloudsmith(const br_scan_ctx *ctx, const char *key,
                                            br_result *result, char **error)
{
    if (!ctx) return SMITH_SKIP;
    const br_header headers[] = {{"Accept", "application/json"}, {"X-Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloudsmith.io/v1/user/self/",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL, *json_cause = NULL;
    cloudsmith_outcome outcome = SMITH_KEEP;
    /* The entire shared setup/allocation + Do failure domain is suppressed.
     * Non-2xx never reads JSON or gives a body/read error priority over status. */
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300) {
        int rc = read_response(response.body, response.body_error, result, &json_cause);
        if (rc < 0) {
            fail(error, "cannot decode Cloudsmith response"); outcome = SMITH_ABORT;
        } else if (rc != 0) {
            const br_slice secret = {result->raw.data, result->raw.len};
            /* Source sets the key-redacted cause, THEN continues the outer key
             * loop. The error is never published, but setter +1 must still be
             * fatal BEFORE SKIP. Copy while response-owned storage is alive. */
            if (br_result_set_verification_error(result, json_cause, &secret, 1)) {
                fail(error, "cannot sanitize Cloudsmith decode error"); outcome = SMITH_ABORT;
            } else outcome = SMITH_SKIP;
        }
    }
    /* Source scan-defers Close ONLY. Eager buffering/release does not establish
     * native streaming, exact diagnostic, lifecycle or full client parity. */
    br_http_release(ctx, &response);
    free(json_cause); free(transport_error);
    return outcome;
}

static int scan_cloudsmith(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Cloudsmith scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; cloudsmith_outcome outcome = SMITH_KEEP;
        br_slice key = br_captures_at(&keys, i); /* TrimSpace is a no-op for lowercase ASCII hex. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Cloudsmith result"); outcome = SMITH_ABORT;
        }
        if (outcome == SMITH_KEEP && verify) outcome = verify_cloudsmith(ctx, keys.items[i], &result, &owned_error);
        if (outcome == SMITH_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Cloudsmith result"); outcome = SMITH_ABORT;
        }
        br_result_clear(&result); /* A normal decode error discards this occurrence only. */
        if (outcome == SMITH_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"cloudsmith"};
static br_detector cloudsmith = {
    .type = 805, .version = 0, .name = "Cloudsmith", .custom_name = "",
    .description = "Cloudsmith is a cloud-native package management service. Cloudsmith API keys can be used to manage and distribute packages.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_cloudsmith,
};

int br_cloudsmith_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Cloudsmith detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloudsmith, "\\b([0-9a-f]{40})\\b", error)) return -1;
    *out = &cloudsmith;
    return 0;
}
