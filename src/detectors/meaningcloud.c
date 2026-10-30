/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/meaningcloud/meaningcloud.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <json-c/json_util.h>
#include <math.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

/* Ordinary error presence is independent of nullable diagnostic storage. */
typedef struct { double deep_time; char *cause; bool has_error; } mc_response;

static int mc_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int mc_number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field response.deepTime of type float64";
    size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - fixed) return -1;
    *cause = malloc(fixed + number.len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

static int mc_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    mc_response *fields = opaque;
    if (!br_json_field_name(name, "deeptime") || !value) return 0;
    if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double)) {
        if (fields->has_error) return 0;
        fields->has_error = true;
        return br_json_type_cause(value, "response.deepTime", "float64", &fields->cause);
    }
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    if (encoded.len == SIZE_MAX) return -1;
    char *token = malloc(encoded.len + 1);
    if (!token) return -1;
    memcpy(token, encoded.data, encoded.len);
    token[encoded.len] = '\0';
    double number = 0;
    /* Parse ORIGINAL numeric bytes, not json-c's possibly saturated value.
     * Finite underflow is accepted even with ERANGE. Keep visiting numeric
     * duplicates after a sticky ordinary error; later owned failures win. */
    bool invalid = json_parse_double(token, &number) != 0 || !isfinite(number);
    int rc = 0;
    if (!invalid) fields->deep_time = number;
    else if (!fields->has_error) {
        fields->has_error = true;
        rc = mc_number_cause(encoded, &fields->cause);
    }
    free(token);
    return rc;
}

static int mc_decode(const br_http_response *response, double *deep_time,
                      bool *has_error, char **cause, char **error)
{
    mc_response fields = {0};
    br_json *document = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &document, &end, &fields.cause);
    if (rc == 1) { /* This API explicitly reserves +1 for ordinary decode failure. */
        json_object_put(document);
        *has_error = true;
        *cause = fields.cause;
        return 0;
    }
    if (rc == 0 && document) {
        if (json_object_is_type(document, json_type_object))
            rc = br_json_each_member((br_slice){response->body.data, end}, mc_member, &fields);
        else {
            fields.has_error = true;
            rc = br_json_type_cause(document, NULL, "meaningcloud.response", &fields.cause);
        }
    }
    json_object_put(document);
    if (rc != 0) {
        free(fields.cause);
        return mc_fail(error, "cannot decode MeaningCloud response");
    }
    *deep_time = fields.deep_time;
    *has_error = fields.has_error;
    *cause = fields.cause;
    return 0;
}

static int mc_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                      bool *drop, char **error)
{
    *drop = false;
    /* NewWriter consumes exactly 30 cryptographic bytes BEFORE the nil-context
     * constructor check. OpenSSL's success domain is exactly 1, not any nonzero. */
    unsigned char random[30];
    if (RAND_bytes(random, sizeof(random)) != 1)
        return mc_fail(error, "cannot generate MeaningCloud multipart boundary");
    static const char hex[] = "0123456789abcdef";
    char boundary[61];
    for (size_t i = 0; i < sizeof(random); ++i) {
        boundary[2 * i] = hex[random[i] >> 4];
        boundary[2 * i + 1] = hex[random[i] & 15];
    }
    boundary[60] = '\0';
    static const char first[] = "\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n";
    static const char next[] = "\r\n--";
    static const char second[] = "\r\nContent-Disposition: form-data; name=\"txt\"\r\n\r\ntest\r\n--";
    static const char finish[] = "--\r\n";
    unsigned char body[327];
    _Static_assert(2 + 60 + sizeof(first) - 1 + 32 + sizeof(next) - 1 + 60 +
                   sizeof(second) - 1 + 60 + sizeof(finish) == sizeof(body),
                   "MeaningCloud multipart body must contain 326 bytes plus NUL");
    size_t at = 0;
    memcpy(body + at, "--", 2); at += 2;
    memcpy(body + at, boundary, 60); at += 60;
    memcpy(body + at, first, sizeof(first) - 1); at += sizeof(first) - 1;
    memcpy(body + at, key.data, 32); at += 32;
    memcpy(body + at, next, sizeof(next) - 1); at += sizeof(next) - 1;
    memcpy(body + at, boundary, 60); at += 60;
    memcpy(body + at, second, sizeof(second) - 1); at += sizeof(second) - 1;
    memcpy(body + at, boundary, 60); at += 60;
    memcpy(body + at, finish, sizeof(finish));
    if (!ctx) { *drop = true; return 0; }

    static const char type_prefix[] = "multipart/form-data; boundary=";
    char content_type[91];
    _Static_assert(sizeof(type_prefix) - 1 + sizeof(boundary) == sizeof(content_type),
                   "MeaningCloud Content-Type must contain 90 bytes plus NUL");
    memcpy(content_type, type_prefix, sizeof(type_prefix) - 1);
    memcpy(content_type + sizeof(type_prefix) - 1, boundary, sizeof(boundary));
    const br_header headers[] = {{"Content-Type", content_type}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.meaningcloud.com/lang-4.0/identification",
        .headers = headers, .nheaders = 1, .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *decode_cause = NULL;
    int rc = 0;
    /* Suppress the WHOLE mixed shared preparation/Do error domain. Non-2xx
     * never decodes, reads or calls the setter. Successful 2xx decodes ONCE. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
        response.status >= 200 && response.status < 300) {
        double deep_time = 0;
        bool decode_error = false;
        rc = mc_decode(&response, &deep_time, &decode_error, &decode_cause, error);
        if (rc == 0 && decode_error) {
            /* Source conditionally sets WITH the key BEFORE ordinary drop.
             * A setter +1 is fatal even though this finding would be discarded.
             * Retain the source setter-before-Close relation; ABI1 releases
             * synchronously below rather than scan-deferring successful Close. */
            if (br_result_set_verification_error(result, decode_cause, &key, 1) != 0)
                rc = mc_fail(error, "cannot set MeaningCloud verification error");
            else *drop = true;
        } else if (rc == 0) result->verified = deep_time > 0;
    }
    /* Original body/type/key/URL survive release, including fatal decode/setter
     * paths. Prepared headers/UA do not survive ordinary send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(decode_cause);
    return rc;
}

static int mc_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mc_fail(error, "invalid or uninitialized MeaningCloud scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool drop = false;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace cannot alter this alphabet. Finding allocation precedes
         * RNG/form preparation, nil-context skips and ordinary decoder drops. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mc_fail(&owned_error, "cannot create MeaningCloud finding");
        if (rc == 0 && verify) rc = mc_verify(ctx, key, &result, &drop, &owned_error);
        if (rc == 0 && !drop && br_results_push(out, &result) != 0)
            rc = mc_fail(&owned_error, "cannot append MeaningCloud finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        mc_fail(&owned_error, "cannot collect MeaningCloud keys");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mc_keywords[] = {"meaningcloud"};
static br_detector mc_detector = {
    .type = 622, .version = 0, .name = "MeaningCloud", .custom_name = "",
    .description = "MeaningCloud is a text analytics service used to extract insights from unstructured content. MeaningCloud API keys can be used to access and utilize these text analytics services.",
    .keywords = mc_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mc_scan,
};

int br_meaningcloud_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mc_fail(error, "invalid MeaningCloud detector output");
    *out = NULL;
    if (!mc_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(mc_keywords, 1, "\\b([a-z0-9]{32})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        mc_detector.state = pattern;
    }
    *out = &mc_detector;
    return 0;
}
