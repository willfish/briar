/* SPDX-License-Identifier: AGPL-3.0-only */
/* Qase, from pinned TruffleHog pkg/detectors/qase/qase.go. Duplicates are kept. */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.qase.io/v1/user";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot store Qase verification error");
        return 0;
    }
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Token", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .timeout_ms = 5000, .detector_type = 761, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format Qase status error");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "cannot store Qase verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Qase scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        const char *key = found.items[i];
        if (br_finding_key(&result, detector->type, key, "key") != 0)
            rc = fail(&owned, "cannot create Qase finding");
        else if (verify_requested && verify(ctx, key, &result, &owned) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Qase finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Qase", .type = 761, .description =
        "Qase is a test management platform that allows users to manage test cases, plans, and runs. Qase API tokens can be used to access and modify test data and settings.",
    .keywords = (const char *[]){"qase", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_qase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Qase detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([0-9a-zA-Z]{40})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
