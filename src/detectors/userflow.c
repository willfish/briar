/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/userflow/userflow.go. */
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

static int verify_userflow(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx) return 1;
    const char *key = (const char *)secret.data;
    size_t key_len = strlen(key);
    if (key_len > SIZE_MAX - 8) return fail(error, "Userflow authorization is too large");
    char *auth = malloc(7 + key_len + 1);
    if (!auth) return fail(error, "cannot format Userflow authorization");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, key, key_len + 1);
    const br_header headers[] = {
        {"Accept", "application/vnd.userflow+json; version=3"},
        {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.userflow.com/users",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 779,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(send_error);
    free(auth);
    return 0;
}

static int scan_userflow(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Userflow scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create Userflow finding");
        } else if (verify) {
            int status = verify_userflow(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Userflow finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"userflow"};
static br_detector userflow = {
    .type = 779, .version = 0, .name = "Userflow", .custom_name = "",
    .description = "Userflow is a service for creating user onboarding experiences. Userflow API keys can be used to access and modify user onboarding data and workflows.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_userflow,
};

int br_userflow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Userflow detector output");
    *out = NULL;
    if (br_key_pattern_init(&userflow, "\\b([0-9a-z_]{29})\\b", error) != 0) return -1;
    *out = &userflow;
    return 0;
}
