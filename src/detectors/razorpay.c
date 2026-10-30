/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/razorpay/razorpay.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>

typedef enum { RAZOR_ABORT = -1, RAZOR_KEEP = 0, RAZOR_SKIP = 1 } razor_outcome;

static int razor_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

__attribute__((weak)) int br_razorpay_json_document(br_slice body, br_json **out, char **cause)
{
    return br_json_document(body, out, cause);
}

static razor_outcome razor_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret,
                                  br_result *result, char **error)
{
    /* SetBasicAuth is after NewRequestWithContext. Nil context drops this
     * pair before encoding. Encoding failure is fatal. The fixed URL cannot
     * fail to parse. */
    if (!ctx) return RAZOR_SKIP;
    char *authorization = NULL;
    if (br_http_basic_auth(key, secret, &authorization, error) != 0) {
        free(authorization);
        return RAZOR_ABORT;
    }
    razor_outcome outcome = RAZOR_KEEP;
    {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.razorpay.com/v1/items?count=1",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Do errors retain the unverified pair; a body-read error drops it.
         * JSON validation is reached only for 2xx. No setter. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
            /* Source falls through to append when client.Do fails. */
        } else if (response.body_error) {
            outcome = RAZOR_SKIP;
        } else if (response.status >= 200 && response.status < 300) {
            br_json *document = NULL;
            char *json_error = NULL;
            int valid = br_razorpay_json_document(response.body, &document, &json_error);
            json_object_put(document);
            if (valid != 0 && valid != 1) {
                razor_fail(error, "cannot inspect RazorPay body");
                free(json_error);
                outcome = RAZOR_ABORT;
            } else {
                free(json_error);
                result->verified = valid == 0;
            }
        }
        br_http_release(ctx, &response);
        free(transport_error);
    }
    free(authorization);
    return outcome;
}

static int razor_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return razor_fail(error, "invalid or uninitialized RazorPay scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    /* Unprefixed key and secret. Ordered duplicates stay. Every key is paired
     * with every secret, including overlapping rescan of the same input. */
    int rc = br_captures_find(patterns[0], input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &secrets, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 23) {
            razor_fail(&owned_error, "invalid RazorPay key capture");
            rc = -1;
            break;
        }
        for (size_t j = 0; j < secrets.len; ++j) {
            br_slice secret = br_captures_at(&secrets, j);
            br_result result = {0};
            razor_outcome outcome = RAZOR_KEEP;
            if (secret.len != 24) {
                razor_fail(&owned_error, "invalid RazorPay secret capture");
                outcome = RAZOR_ABORT;
            } else if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret", (br_slice){0}) != 0 ||
                       !(result.redacted = strndup((const char *)key.data, key.len))) {
                razor_fail(&owned_error, "cannot create RazorPay result");
                outcome = RAZOR_ABORT;
            } else if (verify) {
                outcome = razor_verify(ctx, key, secret, &result, &owned_error);
            }
            if (outcome == RAZOR_KEEP && br_results_push(out, &result) != 0) {
                razor_fail(&owned_error, "cannot append RazorPay result");
                outcome = RAZOR_ABORT;
            }
            br_result_clear(&result);
            if (outcome == RAZOR_ABORT) {
                rc = -1;
                break;
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const razor_keywords[] = {"rzp_live_"};
static br_regex *razor_patterns[2];
static br_detector razor_detector = {
    .type = 11, .version = 0, .name = "RazorPay", .custom_name = "",
    .description = "RazorPay is a payment gateway service that allows businesses to accept, process, and disburse payments. RazorPay keys can be used to access and manage payment transactions.",
    .keywords = razor_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = razor_scan, .state = razor_patterns,
};

int br_razorpay_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return razor_fail(error, "invalid RazorPay detector output");
    *out = NULL;
    if (!razor_patterns[0] &&
        (br_regex_compile("(?i)(\\brzp_live_[A-Za-z0-9]{14}\\b)", &razor_patterns[0], error) != 0 ||
         br_regex_compile("(\\b[A-Za-z0-9]{24}\\b)", &razor_patterns[1], error) != 0))
        return -1;
    *out = &razor_detector;
    return 0;
}
