/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/thinkific/thinkific.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } thinkific_patterns;

static const char thinkific_marker[] = "API Access is not available";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_rest(const char *rest, br_regex **out, char **error)
{
    static const char *const keywords[] = {"thinkific"};
    char *prefix = NULL;
    if (br_prefix_regex(keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate Thinkific prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "Thinkific pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate Thinkific pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int scan_thinkific(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Thinkific scan");
    const thinkific_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->domain, input, &domains, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t d = 0; !rc && d < domains.len; ++d) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice domain = br_captures_at(&domains, d);
            if (key.len != 32 || domain.len < 4 || domain.len > 40 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(&owned_error, "cannot create Thinkific result");
            if (!rc && verify) {
                char subdomain[64], key_header[33];
                int n = snprintf(subdomain, sizeof(subdomain), "%.*s-s-school", (int)domain.len, domain.data);
                if (n < 0 || (size_t)n >= sizeof(subdomain)) {
                    br_result_clear(&result);
                    rc = fail(&owned_error, "cannot build Thinkific subdomain");
                    break;
                }
                /* Subdomain string exists before NewRequestWithContext. Nil context skips. */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                memcpy(key_header, key.data, 32);
                key_header[32] = '\0';
                const br_header headers[] = {
                    {"X-Auth-API-Key", key_header},
                    {"X-Auth-Subdomain", subdomain},
                    {"Content-Type", "application/json"},
                };
                const br_http_request request = {
                    .method = "GET", .url = "https://api.thinkific.com/api/public/v1/collections",
                    .headers = headers, .nheaders = 3,
                    .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = detector->type,
                };
                br_http_response response = {0};
                char *send_error = NULL;
                int sent = br_http_send(ctx, &request, &response, &send_error);
                if (sent == 0 && response.body_error) {
                    /* ReadAll failure continues before append, same as a constructor skip. */
                    br_http_release(ctx, &response);
                    free(send_error);
                    br_result_clear(&result);
                    continue;
                }
                if (sent == 0) {
                    br_slice marker = {(const unsigned char *)thinkific_marker, sizeof(thinkific_marker) - 1};
                    if (br_slice_find(response.body, marker, 0) != (size_t)-1) result.verified = true;
                }
                br_http_release(ctx, &response);
                free(send_error);
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append Thinkific result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static thinkific_patterns patterns;
static const char *const keywords[] = {"thinkific"};
static br_detector thinkific = {
    .type = 589, .version = 0, .name = "Thinkific", .custom_name = "",
    .description = "Thinkific is an online course platform that allows users to create, market, and sell online courses. Thinkific API keys can be used to access and manage course data and user information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_thinkific,
};

int br_thinkific_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Thinkific detector output");
    *out = NULL;
    if (!patterns.key && compile_rest("\\b([0-9a-f]{32})\\b", &patterns.key, error) != 0) return -1;
    if (!patterns.domain && compile_rest("\\b([0-9A-Za-z]{4,40})\\b", &patterns.domain, error) != 0)
        return -1;
    *out = &thinkific;
    return 0;
}
