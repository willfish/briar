/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/stripo/stripo.go. */
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

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

static int verify_stripo(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx) return 1;
    const br_header headers[] = {{"Stripo-Api-Auth", (const char *)secret.data}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://stripo.email/emailgeneration/v1/emails?parameters=sortingAsc=true",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 955,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    bool error_present = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        error_present = true;
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format Stripo status");
        else {
            error_present = true;
            cause = status_error;
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = -1;
    free(send_error);
    return rc;
}

static int scan_stripo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Stripo scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create Stripo finding");
        } else if (verify) {
            int status = verify_stripo(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Stripo finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"stripo"};
static br_detector stripo = {
    .type = 955, .version = 0, .name = "Stripo", .custom_name = "",
    .description = "Stripo is an email template builder. Stripo API keys can be used to access and modify email templates.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_stripo,
};

int br_stripo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Stripo detector output");
    *out = NULL;
    if (br_key_pattern_init(&stripo,
            "\\b(eyJhbGciOiJIUzI1NiJ9\\.[0-9A-Za-z]{130}\\.[0-9A-Za-z_-]{43})\\b", error) != 0)
        return -1;
    *out = &stripo;
    return 0;
}
