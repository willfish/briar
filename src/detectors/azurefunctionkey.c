/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azurefunctionkey. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *url; } function_patterns;
typedef struct { br_slice input; br_captures *values; char *error; } function_matches;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_key(void *user, const br_span *groups, size_t ngroups)
{
    function_matches *matches = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > matches->input.len)
        return fail(&matches->error, "invalid Azure Function key match");
    size_t begin = groups[0].begin, end = groups[0].end;
    /* TrimSpace is a no-op for this match. Source splits GROUP ZERO at literal
     * ASCII spaces only: tabs, NUL, prefixes and optional '=' padding survive. */
    for (size_t i = end; i > begin; --i) {
        if (matches->input.data[i - 1] == ' ') { begin = i; break; }
    }
    return br_captures_push(matches->values,
        (br_slice){matches->input.data + begin, end - begin}, false, &matches->error);
}

static int collect_url(void *user, const br_span *groups, size_t ngroups)
{
    function_matches *matches = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > matches->input.len)
        return fail(&matches->error, "invalid Azure Function URL match");
    return br_captures_push(matches->values,
        (br_slice){matches->input.data + groups[0].begin, groups[0].end - groups[0].begin},
        false, &matches->error);
}

/* 0 candidate outcome, 1 request-creation skip, -1 resource failure. */
static int verify_function(const br_scan_ctx *ctx, br_slice key, br_slice url, br_result *result)
{
    if (!ctx) return 1; /* NewRequestWithContext rejects a nil context upstream. */
    /* net/url.Parse removes the FIRST #fragment before its C0/DEL check.
     * Fragment-only controls do not prove a request-creation failure. */
    for (size_t i = 0; i < key.len; ++i) {
        if (key.data[i] == '#') break;
        if (key.data[i] < 0x20 || key.data[i] == 0x7f) return 1;
    }
    /* Keep raw query bytes literal for a bounded ASCII subset. Fragments,
     * percent forms and Unicode need wider Go URL/transport parity; do not
     * normalize them or pretend an injected 2xx establishes their validity. */
    for (size_t i = 0; i < key.len; ++i) {
        unsigned char c = key.data[i];
        if (c >= 0x80 || c == '#' || c == '%') {
            int stored = br_result_set_verification_error(result,
                "unsupported: Azure Function key URL form", &key, 1);
            return stored ? -1 : 0;
        }
    }
    static const char query[] = "?code=";
    if (key.len > SIZE_MAX - sizeof(query) || url.len > SIZE_MAX - sizeof(query) - key.len)
        return -1;
    size_t len = url.len + sizeof(query) - 1 + key.len;
    char *request_url = malloc(len + 1);
    if (!request_url) return -1;
    memcpy(request_url, url.data, url.len);
    memcpy(request_url + url.len, query, sizeof(query) - 1);
    memcpy(request_url + url.len + sizeof(query) - 1, key.data, key.len);
    request_url[len] = '\0';
    const br_http_request request = {
        .method = "GET", .url = request_url,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 973,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* Source ignores bodies and defers closes until scan return. ABI1 safely
     * releases each response immediately, including populated send failures. */
    int stored = br_result_set_verification_error(result, cause, &key, 1);
    br_http_release(ctx, &response);
    free(error);
    free(request_url);
    return stored ? -1 : 0; /* Core errors may be positive: never turn OOM into a skip. */
}

static int scan_function(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureFunctionKey scan arguments");
    const function_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->url) return fail(error, "uninitialized AzureFunctionKey patterns");
    br_captures keys = {0}, urls = {0};
    function_matches key_matches = {input, &keys, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(compiled->key, input, collect_key, &key_matches, &regex_error);
    if (key_matches.error) { free(regex_error); regex_error = key_matches.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    if (!rc) {
        function_matches url_matches = {input, &urls, NULL};
        regex_error = NULL;
        rc = br_regex_each(compiled->url, input, collect_url, &url_matches, &regex_error);
        if (url_matches.error) { free(regex_error); regex_error = url_matches.error; }
        if (error) *error = regex_error;
        else free(regex_error);
    }
    /* Source preserves both occurrence lists: key-major, URL-minor, no break. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t u = 0; !rc && u < urls.len; ++u) {
            br_result result = {0};
            br_slice url = br_captures_at(&urls, u);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", url, "url", (br_slice){0}) != 0) {
                rc = fail(error, "out of memory creating AzureFunctionKey result");
            } else {
                int outcome = verify ? verify_function(ctx, key, url, &result) : 0;
                if (outcome < 0) rc = fail(error, "could not verify AzureFunctionKey result");
                else if (outcome > 0) { br_result_clear(&result); continue; }
                else if (br_results_push(out, &result) != 0)
                    rc = fail(error, "out of memory appending AzureFunctionKey result");
            }
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&urls);
    return rc;
}

static function_patterns patterns;
static const char *const keywords[] = {"azure"};
static const br_detector function = {
    .type = 973, .version = 0, .name = "AzureFunctionKey", .custom_name = "",
    .description = "Azure Functions is a serverless compute service that lets you run "
                   "event-triggered code without having to explicitly provision or manage "
                   "infrastructure. Azure Function Keys can be used to access and manage these functions.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_function,
};

int br_azurefunctionkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureFunctionKey detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1,
        "\\b([a-zA-Z0-9_-]{20,56})\\b={0,2}", &patterns.key, error) != 0) return -1;
    if (!patterns.url && br_regex_compile(
        "\\bhttps://([a-zA-Z0-9-]{2,30})\\.azurewebsites\\.net/api/([a-zA-Z0-9-]{2,30})\\b",
        &patterns.url, error) != 0) return -1;
    *out = &function;
    return 0;
}
