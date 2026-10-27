/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/copper/copper.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } copper_patterns;
typedef struct { br_json *email; char *cause; } copper_response;

static int copper_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice copper_number_text(br_slice encoded)
{
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    return encoded;
}

static bool copper_valid_id_number(br_slice number)
{
    size_t at = 0;
    bool negative = number.len && number.data[0] == '-';
    if (negative) ++at;
    if (at == number.len) return false;
    uint64_t limit = (uint64_t)INT64_MAX + (negative ? 1u : 0u), magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false;
        uint64_t digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    return true;
}

static int copper_number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field UserApiResponse.id of type int";
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - overhead) return -1;
    *cause = malloc(overhead + number.len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

static int copper_read_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    copper_response *fields = user;
    /* Go null does not reset an earlier assignment to either scalar field. */
    if (!value) return 0;
    if (br_json_field_name(name, "id")) {
        if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
            br_slice number = copper_number_text(encoded);
            if (copper_valid_id_number(number)) return 0;
            return copper_number_cause(number, &fields->cause) == 0 ? 1 : -1;
        }
        return br_json_type_cause(value, "UserApiResponse.id", "int", &fields->cause) == 0 ? 1 : -1;
    }
    if (br_json_field_name(name, "email")) {
        if (!json_object_is_type(value, json_type_string))
            return br_json_type_cause(value, "UserApiResponse.email", "string", &fields->cause) == 0 ? 1 : -1;
        json_object_put(fields->email);
        fields->email = json_object_get(value);
    }
    /* Unknown values, including huge numbers, are ignored by the typed struct. */
    return 0;
}

static int copper_read_response(br_slice body, br_slice id, br_result *result, char **cause)
{
    copper_response fields = {0};
    br_json *root = NULL;
    int rc = br_json_document(body, &root, &fields.cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member(body, copper_read_member, &fields);
        else
            rc = br_json_type_cause(root, NULL, "copper.UserApiResponse", &fields.cause) == 0 ? 1 : -1;
    }
    if (rc == 0) {
        br_slice email = br_json_text(fields.email);
        result->verified = email.len == id.len && !memcmp(email.data, id.data, id.len);
        if (!result->verified) {
            fields.cause = strdup("email mismatch in verification response");
            if (!fields.cause) rc = -1;
        }
    }
    *cause = fields.cause;
    json_object_put(fields.email);
    json_object_put(root);
    /* A normal decode cause is retained; resource/helper failures abort scans. */
    return rc == 0 || (rc == 1 && fields.cause) ? 0 : -1;
}

static int copper_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                         br_result *result, char **error)
{
    const char *cause = NULL;
    char *transport_error = NULL, *json_cause = NULL;
    char status_error[64];
    br_http_response response = {0};
    int rc = 0;
    /* NewRequestWithContext precedes header setup, including the ABI1 gap. */
    if (!ctx) cause = "net/http: nil Context";
    else if (memchr(id.data, '\0', id.len))
        cause = "unsupported: Copper ID contains NUL; ABI1 cannot represent HTTP header value";
    else {
        /* Captures include a trailing NUL and remain live through send/release.
         * NoBody is represented as an empty body, not a pointer-identity claim. */
        const br_header headers[] = {
            {"X-Pw-Accesstoken", (const char *)key.data},
            {"X-Pw-Application", "developer_api"},
            {"X-Pw-Useremail", (const char *)id.data},
            {"Content-Type", "application/json"},
        };
        const br_http_request request = {
            .method = "GET", .url = "https://api.copper.com/developer_api/v1/users/me",
            .headers = headers, .nheaders = 4, .profile = BR_HTTP_SANE,
            .detector_type = 214,
        };
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error ? transport_error : "HTTP transport failed";
        else if (response.status == 200) {
            /* ReadAll failure wins over every JSON outcome, even a valid body. */
            if (response.body_error) cause = response.body_error;
            else {
                if (copper_read_response(response.body, id, result, &json_cause) != 0)
                    rc = copper_fail(error, "cannot decode Copper verification response");
                cause = json_cause;
            }
        } else if (response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code :%d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = copper_fail(error, "cannot format Copper verification status");
            else cause = status_error;
        }
        /* Copy/redact borrowed causes BEFORE releasing response storage. Source
         * drains/closes at verifier return; eager native buffering remains a gap. */
        if (rc == 0 && br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = copper_fail(error, "cannot set Copper verification error");
        br_http_release(ctx, &response);
        free(json_cause);
        free(transport_error);
        return rc == 0 ? 0 : -1;
    }
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return copper_fail(error, "cannot set Copper verification error");
    return 0;
}

static int copper_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return copper_fail(error, "invalid or uninitialized Copper scan");
    const copper_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return copper_fail(error, "uninitialized Copper patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            /* TrimSpace cannot change these captures. Keep every occurrence in
             * key-major/ID-minor order, with independent whole-input matching. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = copper_fail(&owned_error, "cannot create Copper result");
            if (rc == 0 && verify) rc = copper_verify(ctx, key, id, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = copper_fail(&owned_error, "cannot append Copper result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static copper_patterns copper_compiled;
static const char *const copper_keywords[] = {"copper"};
static const br_detector copper_detector = {
    .type = 214, .version = 0, .name = "Copper", .custom_name = "",
    .description = "Copper is a CRM platform that helps businesses manage their relationships with customers and leads. Copper API keys can be used to access and modify customer data and interactions.",
    .keywords = copper_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &copper_compiled, .scan = copper_scan,
};

int br_copper_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return copper_fail(error, "invalid Copper detector output");
    *out = NULL;
    if (!copper_compiled.key) {
        copper_patterns compiled = {0};
        if (br_regex_compile_prefixed(copper_keywords, 1, "\\b([a-z0-9]{32})\\b", &compiled.key, error) != 0 ||
            br_regex_compile("\\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\\b", &compiled.id, error) != 0) {
            br_regex_free(compiled.key);
            br_regex_free(compiled.id);
            return -1;
        }
        copper_compiled = compiled;
    }
    *out = &copper_detector;
    return 0;
}
