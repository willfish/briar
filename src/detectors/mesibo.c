/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mesibo/mesibo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *leaf, *wrapped; } mesibo_failure;

static int mesibo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void mesibo_failure_clear(mesibo_failure *failure)
{
    free(failure->wrapped);
    free(failure->leaf);
    memset(failure, 0, sizeof(*failure));
}

static int mesibo_join(const char *prefix, br_slice middle, const char *suffix, char **out)
{
    *out = NULL;
    size_t first = strlen(prefix), last = strlen(suffix);
    if ((!middle.data && middle.len) || first == SIZE_MAX || last > SIZE_MAX - first - 1 ||
        middle.len > SIZE_MAX - first - last - 1) return -1;
    char *text = malloc(first + middle.len + last + 1);
    if (!text) return -1;
    memcpy(text, prefix, first);
    if (middle.len) memcpy(text + first, middle.data, middle.len);
    memcpy(text + first + middle.len, suffix, last + 1);
    *out = text;
    return 0;
}

static int mesibo_wrap(mesibo_failure *failure, const char *prefix, char **error)
{
    if (!failure->leaf || mesibo_join(prefix,
            (br_slice){(const unsigned char *)failure->leaf, strlen(failure->leaf)}, "", &failure->wrapped) != 0)
        return mesibo_fail(error, "cannot wrap Mesibo verification error");
    return 0;
}

static int mesibo_copy_failure(mesibo_failure *failure, const char *prefix,
                               const char *cause, char **error)
{
    failure->leaf = strdup(cause);
    if (!failure->leaf) return mesibo_fail(error, "cannot copy Mesibo verification cause");
    return mesibo_wrap(failure, prefix, error);
}

static int mesibo_integer_cause(const char *prefix, int64_t value, char **out, char **error)
{
    char number[32];
    int n = snprintf(number, sizeof(number), "%" PRId64, value);
    if (n < 0 || (size_t)n >= sizeof(number) || mesibo_join(prefix,
            (br_slice){(const unsigned char *)number, (size_t)n}, "", out) != 0)
        return mesibo_fail(error, "cannot format Mesibo verification cause");
    return 0;
}

static bool mesibo_json_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static br_slice mesibo_number_token(br_slice encoded)
{
    while (encoded.len && mesibo_json_space(encoded.data[0])) { ++encoded.data; --encoded.len; }
    while (encoded.len && mesibo_json_space(encoded.data[encoded.len - 1])) --encoded.len;
    return encoded;
}

/* The containing JSON is syntax-validated. Parse ORIGINAL decimal integer bytes
 * for the selected 64-bit Go int; json-c values may already be saturated. */
static bool mesibo_int64(br_slice token, int64_t *out)
{
    size_t at = 0;
    bool negative = token.len && token.data[0] == '-';
    if (negative) ++at;
    if (at == token.len) return false;
    uint64_t magnitude = 0, limit = (uint64_t)INT64_MAX + (negative ? 1u : 0u);
    for (; at < token.len; ++at) {
        unsigned char c = token.data[at];
        if (c < '0' || c > '9') return false;
        unsigned int digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    if (!negative) *out = (int64_t)magnitude;
    else if (magnitude == (uint64_t)INT64_MAX + 1u) *out = INT64_MIN;
    else *out = -(int64_t)magnitude;
    return true;
}

typedef struct { int64_t code; char *cause; char **error; } mesibo_projection;

static int mesibo_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    mesibo_projection *projection = user;
    if (!br_json_field_name(name, "code") || !value) return 0; /* Scalar null preserves preceding code. */
    char *cause = NULL;
    if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
        br_slice token = mesibo_number_token(encoded);
        int64_t code;
        if (mesibo_int64(token, &code)) { projection->code = code; return 0; }
        if (mesibo_join("json: cannot unmarshal number ", token,
                " into Go struct field apiResponse.code of type int", &cause) != 0)
            return mesibo_fail(projection->error, "cannot create Mesibo number type cause");
    } else if (br_json_type_cause(value, "apiResponse.code", "int", &cause) != 0) {
        free(cause);
        return mesibo_fail(projection->error, "cannot create Mesibo field type cause");
    }
    if (!cause) return mesibo_fail(projection->error, "missing Mesibo field type cause");
    /* Save the first ordinary type error, but continue every subsequent visit
     * and checked cause operation before returning that sticky error. */
    if (!projection->cause) projection->cause = cause;
    else free(cause);
    return 0;
}

static int mesibo_decode(br_slice body, int64_t *code, char **ordinary, char **error)
{
    br_json *document = NULL;
    char *cause = NULL;
    int parsed = br_json_document(body, &document, &cause);
    int rc = 0;
    if (parsed == 1) {
        if (!cause) rc = mesibo_fail(error, "missing Mesibo JSON decode cause");
    } else if (parsed != 0) {
        rc = mesibo_fail(error, "cannot decode Mesibo response document");
    } else if (document && !json_object_is_type(document, json_type_object)) {
        if (br_json_type_cause(document, NULL, "mesibo.apiResponse", &cause) != 0)
            rc = mesibo_fail(error, "cannot create Mesibo response type cause");
        else if (!cause) rc = mesibo_fail(error, "missing Mesibo response type cause");
    } else if (document) {
        mesibo_projection projection = {.error = error};
        if (br_json_each_member(body, mesibo_member, &projection) != 0) {
            free(projection.cause);
            if (!error || !*error) mesibo_fail(error, "cannot visit Mesibo response fields");
            rc = -1;
        } else {
            *code = projection.code;
            cause = projection.cause;
        }
    }
    json_object_put(document);
    if (rc == 0) { *ordinary = cause; cause = NULL; }
    free(cause);
    return rc;
}

static int mesibo_verify(const br_scan_ctx *ctx, br_slice key, bool *verified,
                         mesibo_failure *failure, char **error)
{
    static const char prefix[] = "{\"op\":\"useradd\",\"token\":\"";
    static const char suffix[] = "\"}";
    unsigned char payload[sizeof(prefix) - 1 + 64 + sizeof(suffix) - 1];
    /* The valid ASCII map has exact sorted keys op,token and cannot ordinarily
     * fail Marshal. Build all 91 payload bytes BEFORE context construction. */
    memcpy(payload, prefix, sizeof(prefix) - 1);
    memcpy(payload + sizeof(prefix) - 1, key.data, key.len);
    memcpy(payload + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix) - 1);
    if (!ctx)
        return mesibo_copy_failure(failure, "failed to create request: ", "net/http: nil Context", error);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.mesibo.com/backend",
        .headers = headers, .nheaders = 1, .body = {payload, sizeof(payload)},
        .profile = BR_HTTP_SANE, .detector_type = 503,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error), rc = 0;
    if (sent != 0) {
        /* The whole mixed preparation/Do domain is an ordinary wrapped error.
         * Explicit cause ownership, never classification of diagnostic text. */
        failure->leaf = send_error;
        send_error = NULL;
        if (!failure->leaf) failure->leaf = strdup("HTTP transport failed");
        rc = mesibo_wrap(failure, "failed to execute request: ", error);
    } else if (response.status != 200) {
        rc = mesibo_integer_cause("unexpected status code: ", response.status, &failure->leaf, error);
    } else if (response.body_error != NULL) {
        rc = mesibo_copy_failure(failure, "failed to read response body: ", response.body_error, error);
    } else if (!response.body.data && response.body.len) {
        rc = mesibo_fail(error, "invalid Mesibo response body slice");
    } else {
        int64_t code = 0;
        rc = mesibo_decode(response.body, &code, &failure->leaf, error);
        if (rc == 0) {
            if (failure->leaf) rc = mesibo_wrap(failure, "failed to unmarshal response body: ", error);
            else if (code == 400) *verified = true;
            else if (code != 401) rc = mesibo_integer_cause("unexpected code field: ", code, &failure->leaf, error);
        }
    }
    /* Provider payload/header/key/URL survive one release per attempt, including
     * guards. Never retain synthesized prepared storage beyond send return.
     * Source helper Close runs before outer verdict/setter/publication, as here. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int mesibo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mesibo_fail(error, "invalid or uninitialized Mesibo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        mesibo_failure failure = {0};
        bool verified = false;
        if (key.len != 64) rc = mesibo_fail(&owned_error, "invalid Mesibo capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mesibo_fail(&owned_error, "cannot create Mesibo finding");
        if (rc == 0 && verify) {
            rc = mesibo_verify(ctx, key, &verified, &failure, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                /* Source SetVerificationError unwraps structured %w wrappers to
                 * their explicit leaf BEFORE redaction. Do not strip error text. */
                if (failure.leaf && br_result_set_verification_error(&result, failure.leaf, &key, 1) != 0)
                    rc = mesibo_fail(&owned_error, "cannot set Mesibo verification error");
            }
        }
        mesibo_failure_clear(&failure);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mesibo_fail(&owned_error, "cannot append Mesibo finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mesibo_keywords[] = {"mesibo"};
static br_detector mesibo_detector = {
    .type = 503, .version = 0, .name = "Mesibo", .custom_name = "",
    .description = "Mesibo is a real-time communication platform that allows developers to add messaging, voice, and video calls to their apps. Mesibo tokens can be used to access and interact with the Mesibo API.",
    .keywords = mesibo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mesibo_scan,
};

int br_mesibo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mesibo_fail(error, "invalid Mesibo detector output");
    *out = NULL;
    if (!mesibo_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(mesibo_keywords, 1, "\\b([0-9A-Za-z]{64})\\b", &regex, error) != 0) {
            br_regex_free(regex);
            return -1;
        }
        mesibo_detector.state = regex;
    }
    *out = &mesibo_detector;
    return 0;
}
