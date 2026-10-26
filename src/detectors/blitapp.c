/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/blitapp/blitapp.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_blitapp(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Source suppresses BOTH creation and Client.Do errors, including nil ctx.
     * Do not let a NULL context select any native/default transport. */
    if (!ctx) return 0;
    const br_header headers[] = {{"API-Key", key}};
    const br_http_request request = {.method = "GET", .url = "https://blitapp.com/api/apps/all",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 523};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) == 0) {
        if (response.status == 200) result->verified = true;
        else if (response.status != 401) {
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
        }
    }
    /* No body/read/drain error affects the result. Source omits ALL secret
     * arguments to SetVerificationError; never introduce error redaction. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0;
}

static int scan_blitapp(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_blitapp, error);
}

static const char *const keywords[] = {"blitapp"};
static br_detector blitapp = {
    .type = 523, .version = 0, .name = "BlitApp", .custom_name = "",
    .description = "BlitApp is a service used for managing applications. BlitApp API keys can be used to access and modify application data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_blitapp,
};

int br_blitapp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BlitApp detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&blitapp, "\\b([a-zA-Z0-9_-]{39})\\b", error) != 0) return -1;
    *out = &blitapp;
    return 0;
}
