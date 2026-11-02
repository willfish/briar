/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/planviewleankit/planviewleankit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *subdomain; } planview_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_rest(const char *const *keywords, size_t count, const char *rest,
                        br_regex **out, char **error)
{
    char *prefix = NULL;
    if (br_prefix_regex(keywords, count, &prefix) != 0)
        return fail(error, "cannot allocate PlanviewLeanKit prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "PlanviewLeanKit pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate PlanviewLeanKit pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int scan_planview(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized PlanviewLeanKit scan");
    const planview_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, subs = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->subdomain, input, &subs, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Source keeps duplicates and walks subdomains outside keys. TrimSpace is a no-op. */
    for (size_t s = 0; !rc && s < subs.len; ++s) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice sub = br_captures_at(&subs, s);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(&owned_error, "cannot create PlanviewLeanKit result");
            if (!rc && verify) {
                char url[96], authorization[160];
                if (sub.len > 25 || key.len != 128) {
                    br_result_clear(&result);
                    rc = fail(&owned_error, "invalid PlanviewLeanKit capture");
                    break;
                }
                snprintf(url, sizeof(url), "https://%.*s.leankit.com/io/account", (int)sub.len, sub.data);
                snprintf(authorization, sizeof(authorization), "Bearer %.*s", (int)key.len, key.data);
                /* URL and Authorization exist before the nil-context constructor drop. */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                const br_header headers[] = {{"Authorization", authorization}};
                const br_http_request request = {
                    .method = "GET", .url = url, .headers = headers, .nheaders = 1,
                    .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = detector->type,
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
                rc = fail(&owned_error, "cannot append PlanviewLeanKit result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&subs);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static planview_patterns patterns;
static const char *const keywords[] = {"planviewleankit", "planview"};
static br_detector planview = {
    .type = 734, .version = 0, .name = "PlanviewLeanKit", .custom_name = "",
    .description = "Planview LeanKit is a visual project delivery tool that enables teams to apply Lean management principles to their work. The detected credential can be used to access and manage LeanKit accounts.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_planview,
};

int br_planviewleankit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid PlanviewLeanKit detector output");
    *out = NULL;
    if (!patterns.key && compile_rest(keywords, 2, "\\b([0-9a-f]{128})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.subdomain && compile_rest(keywords, 2,
            "(?:subdomain).\\b([a-zA-Z][a-zA-Z0-9.-]{1,23}[a-zA-Z0-9])\\b",
            &patterns.subdomain, error) != 0)
        return -1;
    *out = &planview;
    return 0;
}
