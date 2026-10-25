/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/api2cart/api2cart.go. */
#include "detectors.h"
#include "key_scan.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { intptr_t return_code; char *cause; } response_fields;

static br_slice number_text(br_slice encoded)
{
    /* The ordered visitor may include trailing JSON whitespace after a value. */
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    return encoded;
}

static bool parse_return_code(br_slice number, intptr_t *out)
{
    size_t at = 0;
    bool negative = number.len && number.data[0] == '-';
    if (negative) ++at;
    if (at == number.len) return false;
    uintptr_t limit = (uintptr_t)INTPTR_MAX + (negative ? 1u : 0u), magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false; /* Fractions/exponents are not Go ints. */
        uintptr_t digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    if (!negative) *out = (intptr_t)magnitude;
    else if (magnitude == (uintptr_t)INTPTR_MAX + 1u) *out = INTPTR_MIN;
    else *out = -(intptr_t)magnitude;
    return true;
}

static int number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field Response.return_code of type int";
    size_t len = sizeof(prefix) - 1 + number.len + sizeof(suffix);
    *cause = malloc(len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

static int read_return_code(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    response_fields *fields = user;
    if (!br_json_field_name(name, "return_code") || !value) return 0;
    if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
        br_slice number = number_text(encoded_value);
        if (parse_return_code(number, &fields->return_code)) return 0;
        return number_cause(number, &fields->cause) == 0 ? 1 : -1;
    }
    return br_json_type_cause(value, "Response.return_code", "int", &fields->cause) == 0 ? 1 : -1;
}

static int read_response(br_slice body, br_result *result, char **cause)
{
    response_fields fields = {0};
    br_json *root = NULL;
    int rc = br_json_document(body, &root, &fields.cause);
    if (!rc && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member(body, read_return_code, &fields);
        else
            rc = br_json_type_cause(root, NULL, "api2cart.Response", &fields.cause) == 0 ? 1 : -1;
    }
    /* Missing/null fields and a top-level null retain Response's zero value.
     * Duplicate assignments are ordered; null never resets an earlier integer. */
    if (!rc) result->verified = fields.return_code == 0;
    *cause = fields.cause;
    json_object_put(root);
    return rc < 0 ? -1 : 0;
}

static int verify_api2cart(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url), "https://api.api2cart.com/v1.1/account.cart.list.json?api_key=%s", key);
    const br_header headers[] = {{"Accept", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 458,
    };
    br_http_response response = {0};
    char *error = NULL, *json_cause = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            if (response.body_error) cause = response.body_error;
            else {
                rc = read_response(response.body, result, &json_cause);
                cause = json_cause;
            }
            break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream omits secret arguments. Only 200 consumes body-read errors;
     * errors while draining other responses are ignored. Never log the cause. */
    if (!rc) rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(json_cause);
    free(error);
    return rc;
}

static int scan_api2cart(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_api2cart, error);
}

static const char *const keywords[] = {"api2cart"};
static br_detector api2cart = {
    .type = 458, .version = 0, .name = "Api2Cart", .custom_name = "",
    .description = "Api2Cart is a unified shopping cart data interface that allows interaction with "
                   "multiple shopping cart platforms. Api2Cart API keys can be used to access and "
                   "manipulate shopping cart data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_api2cart,
};

int br_api2cart_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Api2Cart detector output");
        return -1;
    }
    *out = NULL;
    if (!api2cart.state && br_key_pattern_init(&api2cart, "\\b([0-9a-f]{32})\\b", error) != 0)
        return -1;
    *out = &api2cart;
    return 0;
}
