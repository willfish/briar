/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/runrunit/runrunit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *user; } runrunit_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_rest(const char *rest, br_regex **out, char **error)
{
    static const char *const keywords[] = {"runrunit"};
    char *prefix = NULL;
    if (br_prefix_regex(keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate RunRunIt prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "RunRunIt pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate RunRunIt pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int scan_runrunit(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized RunRunIt scan");
    const runrunit_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, users = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->user, input, &users, false, &owned_error);
    /* Source walks keys outside user tokens and keeps duplicates. TrimSpace is a no-op. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t u = 0; !rc && u < users.len; ++u) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice user = br_captures_at(&users, u);
            if (key.len != 32 || user.len < 18 || user.len > 20 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(&owned_error, "cannot create RunRunIt result");
            if (!rc && verify) {
                /* NewRequestWithContext runs before either header is added. */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                char key_header[33], user_header[21];
                memcpy(key_header, key.data, 32);
                key_header[32] = '\0';
                memcpy(user_header, user.data, user.len);
                user_header[user.len] = '\0';
                const br_header headers[] = {{"App-Key", key_header}, {"User-Token", user_header}};
                const br_http_request request = {
                    .method = "GET", .url = "https://runrun.it/api/v1.0/users",
                    .headers = headers, .nheaders = 2,
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
                rc = fail(&owned_error, "cannot append RunRunIt result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&users);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static runrunit_patterns patterns;
static const char *const keywords[] = {"runrunit"};
static br_detector runrunit = {
    .type = 369, .version = 0, .name = "RunRunIt", .custom_name = "",
    .description = "RunRunIt is a project management tool. App-Key and User-Token can be used to access and modify project data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_runrunit,
};

int br_runrunit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid RunRunIt detector output");
    *out = NULL;
    if (!patterns.key && compile_rest("\\b([0-9a-f]{32})\\b", &patterns.key, error) != 0) return -1;
    if (!patterns.user && compile_rest("\\b([0-9A-Za-z]{18,20})\\b", &patterns.user, error) != 0)
        return -1;
    *out = &runrunit;
    return 0;
}
