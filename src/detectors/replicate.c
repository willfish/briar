/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/replicate/replicate.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_error(br_result *result, const char *message, const char *key, char **error)
{
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    if (br_result_set_verification_error(result, message, &secret, 1) != 0)
        return fail(error, "cannot record Replicate verification error");
    return 0;
}

static int verify_replicate(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    /* A set Scanner.client and the package default both use the injected transport. */
    if (!ctx) return 1;
    char authorization[64];
    int n = snprintf(authorization, sizeof(authorization), "Token %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization))
        return fail(error, "cannot format Replicate authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.replicate.com/v1/predictions",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 967,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) rc = set_error(result, send_error, key, error);
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        char message[64];
        int formatted = snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = fail(error, "cannot format Replicate status");
        else rc = set_error(result, message, key, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_replicate(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Replicate scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int drop = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Replicate result");
        else if (verify) drop = verify_replicate(ctx, keys.items[i], &result, error);
        if (rc == 0 && drop < 0) rc = -1;
        else if (rc == 0 && drop == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append Replicate result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const replicate_keywords[] = {"replicate", "r8_"};
static br_regex *replicate_regex;
static br_detector replicate_detector = {
    .type = 967, .version = 0, .name = "Replicate", .custom_name = "",
    .description = "Replicate is a platform for running machine learning models in the cloud. Replicate API keys can be used to manage and run these models.",
    .keywords = replicate_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_replicate,
};

int br_replicate_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Replicate detector output");
    *out = NULL;
    if (!replicate_regex &&
        br_regex_compile("\\b(r8_[0-9A-Za-z-_]{37})\\b", &replicate_regex, error) != 0)
        return -1;
    replicate_detector.state = replicate_regex;
    *out = &replicate_detector;
    return 0;
}
