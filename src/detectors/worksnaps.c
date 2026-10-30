/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/worksnaps/worksnaps.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_worksnaps(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Worksnaps scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Worksnaps result");
        if (!rc && verify) {
            char *authorization = NULL;
            char *auth_error = NULL;
            /* Encode key:ignored before NewRequestWithContext. Encoding failure is fatal. */
            if (br_http_basic_auth(key, (br_slice){(const unsigned char *)"ignored", 7},
                                   &authorization, &auth_error) != 0) {
                free(auth_error);
                br_result_clear(&result);
                rc = fail(&owned_error, "cannot encode Worksnaps authorization");
                break;
            }
            free(auth_error);
            if (!ctx) {
                free(authorization);
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {{"Authorization", authorization}};
            const br_http_request request = {
                .method = "GET", .url = "https://api.worksnaps.com/api/projects.xml",
                .headers = headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                response.status >= 200 && response.status < 300)
                result.verified = true;
            br_http_release(ctx, &response);
            free(send_error);
            free(authorization);
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append Worksnaps result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"worksnaps"};
static br_detector worksnaps = {
    .type = 687, .version = 0, .name = "Worksnaps", .custom_name = "",
    .description = "Worksnaps is a time tracking service that helps manage and monitor remote work. Worksnaps API keys can be used to access and manage project data and time tracking information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_worksnaps,
};

int br_worksnaps_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Worksnaps detector output");
    *out = NULL;
    if (br_key_pattern_init(&worksnaps, "\\b([0-9A-Za-z]{40})\\b", error) != 0) return -1;
    *out = &worksnaps;
    return 0;
}
