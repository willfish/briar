/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/travisci/travisci.go. */
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

static int scan_travisci(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TravisCI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 22 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create TravisCI result");
        if (!rc && verify) {
            char authorization[32];
            memcpy(authorization, "token ", 6);
            memcpy(authorization + 6, key.data, 22);
            authorization[28] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {
                {"Authorization", authorization},
                {"User-Agent", "API Explorer"},
                {"Travis-API-Version", "3"},
            };
            const br_http_request request = {
                .method = "GET", .url = "https://api.travis-ci.com/user",
                .headers = headers, .nheaders = 3,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                response.status >= 200 && response.status < 300)
                result.verified = true;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append TravisCI result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"travis"};
static br_detector travisci = {
    .type = 29, .version = 0, .name = "TravisCI", .custom_name = "",
    .description = "Travis CI is a continuous integration service used to build and test software projects hosted on GitHub and Bitbucket. Travis CI tokens can be used to interact with the Travis CI API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_travisci,
};

int br_travisci_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TravisCI detector output");
    *out = NULL;
    if (br_key_pattern_init(&travisci, "\\b([a-zA-Z0-9A-Z_]{22})\\b", error) != 0) return -1;
    *out = &travisci;
    return 0;
}
