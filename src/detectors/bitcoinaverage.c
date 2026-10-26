/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitcoinaverage. */
#include "detectors.h"
#include "key_scan.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bool success; char *cause; } response_fields;

static int read_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    response_fields *fields = user;
    /* Null is a no-op for both primitive struct fields, including duplicates. */
    if (!value) return 0;
    if (br_json_field_name(name, "msg")) {
        /* Msg is unused, but a wrong type still invalidates the whole Decode. */
        if (!json_object_is_type(value, json_type_string))
            return br_json_type_cause(value, "response.msg", "string", &fields->cause) == 0 ? 1 : -1;
    } else if (br_json_field_name(name, "success")) {
        if (!json_object_is_type(value, json_type_boolean))
            return br_json_type_cause(value, "response.success", "bool", &fields->cause) == 0 ? 1 : -1;
        fields->success = json_object_get_boolean(value);
    }
    /* Unknown fields are skipped, not converted through a float64 map. */
    return 0;
}

/* Return 0 for a candidate outcome (including an owned decode cause), -1 only
 * for resources. Decoder/visitor +1 means a decode cause, not success. */
static int read_response(br_slice body, const char *read_error, br_result *result, char **cause)
{
    response_fields fields = {0};
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields.cause);
    if (!rc && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, read_field, &fields);
        else
            rc = br_json_type_cause(root, NULL, "bitcoinaverage.response", &fields.cause) == 0 ? 1 : -1;
    }
    /* Ordered visits stop on the first type error; later valid duplicates cannot
     * hide it. Never verify a partially assigned Success after Decode failed. */
    if (!rc) result->verified = fields.success;
    json_object_put(root);
    *cause = fields.cause;
    return rc < 0 ? -1 : 0;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    /* Unlike JSON decode +1, the core setter's +1 is a resource failure. */
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int verify_bitcoinaverage(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    const br_header headers[] = {{"x-ba-key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://apiv2.bitcoinaverage.com/websocket/v3/get_ticket",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 432,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *json_cause = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            /* Decode consumes only the first document: no ReadAll precheck.
             * A complete object may succeed despite a later read error. */
            rc = read_response(response.body, response.body_error, result, &json_cause);
            cause = json_cause;
            break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    if (!rc) rc = set_cause(result, cause);
    /* Drain/close errors cannot change status-only branches. ABI1 eagerly
     * releases each response; native streaming timing parity is not established. */
    br_http_release(ctx, &response);
    free(json_cause);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_bitcoinaverage(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_bitcoinaverage, error);
}

static const char *const keywords[] = {"bitcoinaverage"};
static br_detector bitcoinaverage = {
    .type = 432, .version = 0, .name = "BitcoinAverage", .custom_name = "",
    .description = "BitcoinAverage is a service that provides cryptocurrency market data. "
                   "BitcoinAverage API keys can be used to access and retrieve this market data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bitcoinaverage,
};

int br_bitcoinaverage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BitcoinAverage detector output");
        return -1;
    }
    *out = NULL;
    if (!bitcoinaverage.state && br_key_pattern_init(&bitcoinaverage,
        "\\b([a-zA-Z0-9]{43})\\b", error) != 0) return -1;
    *out = &bitcoinaverage;
    return 0;
}
