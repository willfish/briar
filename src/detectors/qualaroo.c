/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/qualaroo/qualaroo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_error(br_result *result, const char *message, br_slice key, char **error)
{
    /* NULL diagnostic is a checked no-op, but a known error still reaches the setter. */
    if (br_result_set_verification_error(result, message, &key, 1) != 0)
        return fail(error, "cannot record Qualaroo verification error");
    return 0;
}

static int verify_qualaroo(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    if (!ctx) return set_error(result, "net/http: nil Context", secret, error);
    char authorization[80];
    int n = snprintf(authorization, sizeof(authorization), "Basic %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization))
        return fail(error, "cannot format Qualaroo authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.qualaroo.com/api/v1/nudges",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 229,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) rc = set_error(result, send_error, secret, error);
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        char message[64];
        int formatted = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = fail(error, "cannot format Qualaroo status");
        else rc = set_error(result, message, secret, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_qualaroo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Qualaroo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Qualaroo result");
        else if (verify && verify_qualaroo(ctx, keys.items[i], &result, error) != 0)
            rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append Qualaroo result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const qualaroo_keywords[] = {"qualaroo"};
static br_detector qualaroo_detector = {
    .type = 229, .version = 0, .name = "Qualaroo", .custom_name = "",
    .description = "Qualaroo is a customer survey tool that helps in collecting feedback from users. Qualaroo API keys can be used to access and manage survey data.",
    .keywords = qualaroo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_qualaroo,
};

int br_qualaroo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Qualaroo detector output");
    *out = NULL;
    /* No trailing boundary: a longer class run still captures the first 64. */
    if (br_key_pattern_init(&qualaroo_detector, "\\b([a-z0-9A-Z=]{64})", error) != 0) return -1;
    *out = &qualaroo_detector;
    return 0;
}
