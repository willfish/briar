/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/buildkite/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_json *scopes;
    size_t scopes_len;
    char *cause;
} response_fields;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int type_error(response_fields *fields, br_json *value, const char *field, const char *type)
{
    return br_json_type_cause(value, field, type, &fields->cause) == 0 ? 1 : -1;
}

static int read_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    response_fields *fields = user;
    if (!br_json_field_name(name, "scopes")) return 0;
    if (value && !json_object_is_type(value, json_type_array))
        return type_error(fields, value, "APIResponse.scopes", "[]string");
    size_t count = value ? json_object_array_length(value) : 0;
    for (size_t i = 0; i < count; ++i) {
        br_json *item = json_object_array_get_idx(value, i);
        if (item && !json_object_is_type(item, json_type_string))
            return type_error(fields, item, "APIResponse.scopes", "string");
    }
    if (!count) {
        /* Both JSON null and [] discard the old backing slots. */
        json_object_put(fields->scopes);
        fields->scopes = json_object_get(value);
        fields->scopes_len = 0;
        return 0;
    }
    if (count > INT_MAX) return -1;
    if (!fields->scopes) fields->scopes = json_object_new_array_ext((int)count);
    if (!fields->scopes) return -1;
    /* Match Go []string assignment, as in the native Algolia typed decoder:
     * null preserves an existing slot, including slots beyond a prior shrink.
     * Keep backing length here; only scopes_len controls the final join. */
    for (size_t i = 0; i < count; ++i) {
        br_json *item = json_object_array_get_idx(value, i);
        if (item || i >= json_object_array_length(fields->scopes)) {
            br_json *owned = json_object_get(item);
            if (json_object_array_put_idx(fields->scopes, i, owned)) {
                json_object_put(owned);
                return -1;
            }
        }
    }
    fields->scopes_len = count;
    return 0;
}

static int publish_scopes(const response_fields *fields, br_result *result)
{
    size_t count = fields->scopes_len;
    if (count && count - 1 > SIZE_MAX / 2) return -1;
    size_t len = count ? 2 * (count - 1) : 0;
    for (size_t i = 0; i < count; ++i) {
        br_slice text = br_json_text(json_object_array_get_idx(fields->scopes, i));
        if (text.len > SIZE_MAX - len) return -1;
        len += text.len;
    }
    if (len > INT_MAX) return -1;
    unsigned char *joined = malloc(len + 1);
    if (!joined) return -1;
    size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        br_slice text = br_json_text(json_object_array_get_idx(fields->scopes, i));
        if (i) { joined[at++] = ','; joined[at++] = ' '; }
        if (text.len) memcpy(joined + at, text.data, text.len);
        at += text.len;
    }
    joined[at] = '\0';
    br_json *scopes = json_object_new_string_len((const char *)joined, (int)len);
    free(joined);
    if (!scopes) return -1;
    br_json *extra = json_object_new_object();
    if (!extra) { json_object_put(scopes); return -1; }
    if (json_object_object_add(extra, "scopes", scopes)) {
        json_object_put(scopes);
        json_object_put(extra);
        return -1;
    }
    result->extra_data = extra;
    result->verified = true;
    return 0;
}

/* Return 0 for success OR a candidate decode cause; -1 only for resources. */
static int read_response(br_slice body, const char *read_error, br_result *result, char **cause)
{
    response_fields fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (!rc && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, read_field, &fields);
        else rc = type_error(&fields, root, NULL, "buildkite.APIResponse");
    }
    /* Root null, missing/null/empty scopes all verify with an empty string.
     * Preserve order and duplicates: there is NO Algolia filtering or sorting. */
    if (!rc) rc = publish_scopes(&fields, result);
    json_object_put(root);
    json_object_put(fields.scopes);
    *cause = fields.cause;
    return rc < 0 ? -1 : 0;
}

static int set_cause(br_result *result, const char *cause, char **error)
{
    const br_slice token = {result->raw.data, result->raw.len};
    if (br_result_set_verification_error(result, cause, &token, 1))
        return fail(error, "cannot store Buildkite verification error");
    return 0;
}

/* V2 explicitly delegates to V1.VerifyBuildKite upstream. */
static int verify_buildkite(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    json_object_put(result->extra_data);
    result->extra_data = NULL; /* Every verify outcome replaces the NoV metadata. */
    if (!ctx) return set_cause(result, "net/http: nil Context", error);
    char auth[sizeof("Bearer ") + 45];
    int n = snprintf(auth, sizeof(auth), "Bearer %.*s", (int)token.len, (const char *)token.data);
    if (n < 0 || (size_t)n >= sizeof(auth)) return fail(error, "cannot construct Buildkite Authorization header");
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.buildkite.com/v2/access-token",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *json_cause = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status == 200) {
        /* Stream Decode, not ReadAll: a complete first object may ignore a
         * later read error; syntax/read precedence belongs to the helper. */
        rc = read_response(response.body, response.body_error, result, &json_cause);
        cause = json_cause;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    if (!rc) rc = set_cause(result, cause, error);
    else if (error) *error = strdup("cannot decode Buildkite response");
    /* Copy borrowed errors before release. Source ignores non-200 drain errors;
     * ABI1 eager release does not establish native streaming/drain timing. */
    br_http_release(ctx, &response);
    free(json_cause);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_buildkite(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Buildkite scan");
    br_captures tokens = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &tokens, false, &owned_error);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key"))
            rc = fail(&owned_error, "cannot create Buildkite result");
        if (!rc && detector->version == 1) {
            result.extra_data = json_object_new_object(); /* Source V1 NoV has {}, not nil. */
            if (!result.extra_data) rc = fail(&owned_error, "cannot allocate Buildkite v1 metadata");
        }
        if (!rc && verify) rc = verify_buildkite(ctx, token, &result, &owned_error);
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Buildkite result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const v1_keywords[] = {"buildkite"};
static const char *const v2_keywords[] = {"bkua_"};
static br_detector v1 = {
    .type = 142, .version = 1, .name = "Buildkite", .custom_name = "",
    .description = "Buildkite is a platform for running fast, secure, and scalable continuous integration pipelines. Buildkite API tokens can be used to access and modify pipeline data and configurations.",
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_buildkite,
};
static br_detector v2 = {
    .type = 142, .version = 2, .name = "Buildkite", .custom_name = "",
    .description = "Buildkite is a platform for running fast, secure, and scalable continuous integration and delivery pipelines. Buildkite access tokens can be used to interact with the Buildkite API.",
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_buildkite,
};

int br_buildkite_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Buildkite v1 detector output");
    *out = NULL;
    if (br_key_pattern_init(&v1, "\\b([a-z0-9]{40})\\b", error)) return -1;
    *out = &v1;
    return 0;
}

int br_buildkite_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Buildkite v2 detector output");
    *out = NULL;
    if (!v2.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(bkua_[a-z0-9]{40})\\b", &pattern, error)) return -1;
        v2.state = pattern;
    }
    *out = &v2;
    return 0;
}
