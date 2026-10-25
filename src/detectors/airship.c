/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/airship/airship.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_airship(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[sizeof("Bearer ") + 91];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.urbanairship+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://go.urbanairship.com/api/schedules",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 277,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the body but ignores both errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream passes no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_airship(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_airship, error);
}

static const char *const keywords[] = {"airship"};
static br_detector airship = {
    .type = 277, .version = 0, .name = "Airship", .custom_name = "",
    .description = "Airship is a customer engagement platform that provides tools for mobile app "
                   "messaging, in-app messaging, and web notifications. Airship API keys can be "
                   "used to access and manage these messaging services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_airship,
};

int br_airship_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Airship detector output");
        return -1;
    }
    *out = NULL;
    if (!airship.state &&
        br_key_pattern_init(&airship, "\\b([0-9a-zA-Z]{91})\\b", error) != 0)
        return -1;
    *out = &airship;
    return 0;
}
