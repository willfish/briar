/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/vouchery/vouchery.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *subdomain; } vouchery_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_rest(const char *rest, br_regex **out, char **error)
{
    static const char *const keywords[] = {"vouchery"};
    char *prefix = NULL;
    if (br_prefix_regex(keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate Vouchery prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "Vouchery pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate Vouchery pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int scan_vouchery(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Vouchery scan");
    const vouchery_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, subs = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->subdomain, input, &subs, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < subs.len; ++s) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice sub = br_captures_at(&subs, s);
            if (key.len != 36 || sub.len < 2 || sub.len > 20 ||
                br_finding_pair_bytes(&result, detector->type, key, "key", sub, "subdomain",
                                      (br_slice){0}) != 0)
                rc = fail(&owned_error, "cannot create Vouchery result");
            if (!rc && verify) {
                char url[80];
                int n = snprintf(url, sizeof(url), "https://%.*s.vouchery.io/api/v2.0/users",
                                 (int)sub.len, sub.data);
                if (n < 0 || (size_t)n >= sizeof(url)) {
                    br_result_clear(&result);
                    rc = fail(&owned_error, "cannot build Vouchery URL");
                    break;
                }
                br_go_url_parts parts = {0};
                br_go_url_error rejection = {0};
                char *fatal = NULL;
                int parsed = br_go_url_parse((br_slice){(const unsigned char *)url, (size_t)n},
                                             &parts, &rejection, &fatal);
                br_go_url_clear(&parts);
                if (parsed != 0) {
                    free(fatal);
                    br_result_clear(&result);
                    rc = fail(&owned_error, "cannot parse Vouchery URL");
                    break;
                }
                /* NewRequest returns a parse or nil-context error and continues before append. */
                if (rejection.kind != BR_GO_URL_OK || !ctx) {
                    br_result_clear(&result);
                    continue;
                }
                char authorization[48];
                memcpy(authorization, "Bearer ", 7);
                memcpy(authorization + 7, key.data, 36);
                authorization[43] = '\0';
                const br_header headers[] = {{"Authorization", authorization}};
                const br_http_request request = {
                    .method = "GET", .url = url, .headers = headers, .nheaders = 1,
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
                rc = fail(&owned_error, "cannot append Vouchery result");
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

static vouchery_patterns patterns;
static const char *const keywords[] = {"vouchery"};
static br_detector vouchery = {
    .type = 374, .version = 0, .name = "Vouchery", .custom_name = "",
    .description = "Vouchery is a service that provides API keys for accessing their promotional and loyalty campaign management platform. These keys can be used to manage and track various promotional activities.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_vouchery,
};

int br_vouchery_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Vouchery detector output");
    *out = NULL;
    if (!patterns.key && compile_rest("\\b([a-z0-9-]{36})\\b", &patterns.key, error) != 0) return -1;
    if (!patterns.subdomain &&
        compile_rest("\\b([a-zA-Z0-9-\\S]{2,20})\\b", &patterns.subdomain, error) != 0)
        return -1;
    *out = &vouchery;
    return 0;
}
