/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, azuredevopspersonalaccesstoken.go and
 * common/utils.go. The bounded line policy follows Go 1.26.7 bufio.Scanner;
 * it is not a streaming Reader/Scanner compatibility implementation. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *organization; } devops_pat_patterns;
typedef enum { DEVOPS_PAT_MISSING, DEVOPS_PAT_FOUND, DEVOPS_PAT_READ_SHAPE } devops_pat_match;

static int devops_pat_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static devops_pat_match devops_pat_scan_lines(br_slice body)
{
    static const unsigned char marker[] = "lastUpdateTime", newline[] = "\n";
    const size_t limit = 65536;
    size_t at = 0;
    while (at < body.len) {
        size_t remaining = body.len - at;
        br_slice window = {body.data + at, remaining < limit ? remaining : limit};
        size_t lf = br_slice_find(window, (br_slice){newline, 1}, 0);
        if (lf == SIZE_MAX && remaining > limit) return DEVOPS_PAT_MISSING;
        size_t len = lf == SIZE_MAX ? remaining : lf;
        if (len && window.data[len - 1] == '\r') --len;
        bool found = br_slice_find((br_slice){window.data, len},
                                   (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        if (found) {
            /* With no LF and exactly a full buffer, Scanner yields the token
             * only if EOF/error accompanied its final bytes. ABI 1 has no
             * read-chunk timing, so this one marker-bearing case is guarded. */
            if (lf == SIZE_MAX && remaining == limit) return DEVOPS_PAT_READ_SHAPE;
            return DEVOPS_PAT_FOUND;
        }
        if (lf == SIZE_MAX) return DEVOPS_PAT_MISSING;
        at += lf + 1;
    }
    return DEVOPS_PAT_MISSING;
}

static int devops_pat_verify(const br_scan_ctx *ctx, const char *key,
                              const char *organization, br_result *result, char **error)
{
    char url[128]; /* Captured organizations are at most 50 ASCII bytes. */
    snprintf(url, sizeof(url), "https://dev.azure.com/%s/_apis/projects", organization);
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){0}, (br_slice){(const unsigned char *)key, strlen(key)},
                           &authorization, error)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 972,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Source calls ResponseContainsSubstring before inspecting status and
         * ignores its error. A short final marker line survives body_error;
         * an early matching line also wins over later oversized/error data. */
        devops_pat_match match = devops_pat_scan_lines(response.body);
        if (response.status >= 200 && response.status < 300 && match == DEVOPS_PAT_FOUND)
            result->verified = true;
        else if (response.status >= 200 && response.status < 300 && match == DEVOPS_PAT_READ_SHAPE)
            cause = "unsupported: Azure DevOps PAT Scanner read shape for a 65536-byte final marker line";
        else if (response.status != 401) {
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (rc) return devops_pat_fail(error, "out of memory recording Azure DevOps PAT verification error");
    return 0;
}

static int devops_pat_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return devops_pat_fail(error, "invalid Azure DevOps PAT scan arguments");
    const devops_pat_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->organization)
        return devops_pat_fail(error, "uninitialized Azure DevOps PAT detector");
    /* NewRequestWithContext(nil, ...) fails; source continues without emitting
     * that candidate. All other URL bytes are safe by the capture alphabet. */
    if (verify && !ctx) return 0;
    size_t original_len = out->len;
    br_captures keys = {0}, organizations = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(patterns->organization, input, &organizations, false, error);
    /* TrimSpace is a no-op. Retain occurrences and the complete key-major,
     * organization-minor product, even after a successful verification. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t o = 0; !rc && o < organizations.len; ++o) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                organizations.items[o], "organization"))
                rc = devops_pat_fail(error, "out of memory creating Azure DevOps PAT result");
            else if (verify) rc = devops_pat_verify(ctx, keys.items[k], organizations.items[o], &result, error);
            if (!rc && br_results_push(out, &result))
                rc = devops_pat_fail(error, "out of memory appending Azure DevOps PAT result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&organizations);
    return rc;
}

static devops_pat_patterns devops_pat_compiled;
static const char *const devops_pat_keywords[] = {"azure"};
static const br_detector devops_pat_detector = {
    .type = 972, .version = 0, .name = "AzureDevopsPersonalAccessToken", .custom_name = "",
    .description = "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) "
                   "are used to authenticate and authorize access to Azure DevOps services and resources.",
    .keywords = devops_pat_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &devops_pat_compiled, .scan = devops_pat_scan,
};

int br_azuredevopspersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return devops_pat_fail(error, "invalid Azure DevOps PAT detector output");
    *out = NULL;
    /* PrefixRegex folds only its keyword; the key capture stays lowercase. */
    if (!devops_pat_compiled.key && br_regex_compile_prefixed(devops_pat_keywords, 1,
        "\\b([0-9a-z]{52})\\b", &devops_pat_compiled.key, error)) return -1;
    if (!devops_pat_compiled.organization && br_regex_compile_prefixed(devops_pat_keywords, 1,
        "\\b([0-9a-zA-Z][0-9a-zA-Z-]{5,48}[0-9a-zA-Z])\\b", &devops_pat_compiled.organization, error)) return -1;
    *out = &devops_pat_detector;
    return 0;
}
