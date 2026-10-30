/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/userstack/userstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    return br_slice_find(body, (br_slice){(const unsigned char *)needle, n}, 0) != SIZE_MAX;
}

static int verify_userstack(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[96];
    int n = snprintf(url, sizeof(url), "https://api.userstack.com/detect?access_key=%s&ua=Mozilla/5.0", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    /* Status is ignored. ReadAll and Do errors leave the finding unverified.
     * Either marker verifies, including the documented HTTPS-plan refusal. */
    if (br_http_send(ctx, &request, &response, &error) == 0 && !response.body_error)
        result->verified = contains(response.body, "is_mobile_device") ||
            contains(response.body, "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"");
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_userstack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized UserStack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(error, "out of memory creating UserStack result");
        else if (verify) {
            int checked = verify_userstack(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct UserStack URL");
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending UserStack result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"userstack"};
static br_detector userstack = {
    .type = 541, .version = 0, .name = "UserStack", .custom_name = "",
    .description = "UserStack is a service that provides detailed information about the technology stack used by a website. UserStack API keys can be used to access this information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_userstack,
};

int br_userstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid UserStack detector output");
    *out = NULL;
    if (br_key_pattern_init(&userstack, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &userstack;
    return 0;
}
