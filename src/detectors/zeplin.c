/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zeplin/zeplin.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zeplin_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 : -1;
    char authorization[sizeof("Bearer ") + 400];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", authorization}};
    /* http.NoBody sends no body. Deferred drain and close errors are ignored. */
    const br_http_request request = {
        .method = "GET", .url = "https://api.zeplin.dev/v1/users/me",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 155,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else switch (response.status) {
    case 200: result->verified = true; break;
    case 401: break;
    default:
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
        break;
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1) == 0 ? 0 : -1;
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int zeplin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", zeplin_verify, error);
}

static const char *const zeplin_keywords[] = {"zeplin"};
static br_detector zeplin_detector = {
    .type = 155, .version = 0, .name = "Zeplin", .custom_name = "",
    .description = "Zeplin is a collaboration app for UI designers and front-end developers. Zeplin API keys can be used to access and modify project data.",
    .keywords = zeplin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zeplin_scan,
};

int br_zeplin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Zeplin detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&zeplin_detector, "\\b([a-zA-Z0-9-.]{350,400})\\b", error) != 0)
        return -1;
    *out = &zeplin_detector;
    return 0;
}
