/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/azuresearchquerykey/azuresearchquerykey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *url, *canonical; } search_patterns;
typedef struct { br_slice input; br_captures values; char *error; } search_urls;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_url(void *user, const br_span *groups, size_t ngroups)
{
    search_urls *urls = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > urls->input.len)
        return fail(&urls->error, "invalid Azure Search query URL capture");
    br_slice value = {urls->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    /* TrimSpace is a no-op: full match starts with azure and ends with an index
     * byte. Source splits match[0] on LITERAL ASCII SPACE and takes its last
     * field, not captures 1/2, generic whitespace, or the https suffix. */
    size_t begin = 0;
    for (size_t i = 0; i < value.len; ++i) if (value.data[i] == ' ') begin = i + 1;
    value.data += begin; value.len -= begin;
    return br_captures_push(&urls->values, value, false, &urls->error);
}

static int found_url(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups; (void)ngroups;
    *(bool *)user = true;
    return 0;
}

/* 0 is a candidate outcome; -1 is a resource error. Skip is a separate output,
 * never a numeric sentinel that could collide with positive core failures. */
static int verify_search(const br_detector *detector, const br_scan_ctx *ctx, br_slice endpoint,
                           const char *key, br_result *result, bool *skip, char **error)
{
    *skip = false;
    if (!ctx) { *skip = true; return 0; } /* NewRequestWithContext creation failure. */
    static const unsigned char hash[] = "#";
    size_t fragment = br_slice_find(endpoint, (br_slice){hash, 1}, 0);
    size_t prefix = fragment == SIZE_MAX ? endpoint.len : fragment;
    for (size_t i = 0; i < prefix; ++i) {
        if (endpoint.data[i] < 0x20 || endpoint.data[i] == 0x7f) {
            *skip = true; return 0; /* Known creation error, source continues. */
        }
    }
    bool supported = fragment == SIZE_MAX;
    for (size_t i = 0; supported && i < endpoint.len; ++i)
        if (endpoint.data[i] == '%' || endpoint.data[i] >= 0x80) supported = false;
    if (supported) {
        const search_patterns *patterns = detector->state;
        bool canonical = false;
        if (br_regex_each(patterns->canonical, endpoint, found_url, &canonical, error) != 0) return -1;
        supported = canonical;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    if (!supported) {
        /* A fragment can hide controls from Go's URL parser. It is NOT a known
         * creation failure; retain a fail-closed candidate and continue pairs. */
        if (br_result_set_verification_error(result,
            "unsupported: Azure Search query URL outside canonical ASCII subset", &secret, 1) != 0)
            return fail(error, "out of memory recording Azure Search query verification error");
        return 0;
    }
    static const char suffix[] = "/docs/$count?api-version=2023-10-01-Preview";
    if (endpoint.len > SIZE_MAX - sizeof(suffix))
        return fail(error, "Azure Search query request URL too large");
    char *request_url = malloc(endpoint.len + sizeof(suffix));
    if (!request_url) return fail(error, "out of memory constructing Azure Search query request");
    memcpy(request_url, endpoint.data, endpoint.len);
    memcpy(request_url + endpoint.len, suffix, sizeof(suffix));
    const br_header headers[] = {{"api-key", key}};
    const br_http_request request = {.method = "GET", .url = request_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 977};
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* Body/read errors are ignored. Never retry PUBLIC failures through SANE. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error); free(request_url);
    if (rc != 0) return fail(error, "out of memory recording Azure Search query verification error");
    return 0;
}

static int scan_search(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure Search query scan arguments");
    const search_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->url || !patterns->canonical)
        return fail(error, "uninitialized Azure Search query patterns");
    size_t original_len = out->len;
    br_captures keys = {0};
    search_urls urls = {.input = input};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (!rc) {
        char *regex_error = NULL;
        rc = br_regex_each(patterns->url, input, collect_url, &urls, &regex_error);
        if (urls.error) { free(regex_error); regex_error = urls.error; }
        if (error) *error = regex_error;
        else free(regex_error);
    }
    /* Preserve occurrences and the complete key-major/URL-minor product. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t u = 0; !rc && u < urls.values.len; ++u) {
            br_result result = {0};
            bool skip = false;
            br_slice endpoint = br_captures_at(&urls.values, u);
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                       endpoint, "url", (br_slice){0}) != 0)
                rc = fail(error, "out of memory creating Azure Search query result");
            else if (verify) rc = verify_search(detector, ctx, endpoint, keys.items[k], &result, &skip, error);
            if (!rc && !skip && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending Azure Search query result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&urls.values);
    return rc ? -1 : 0;
}

static search_patterns patterns;
static const char *const keywords[] = {"azure"};
static const br_detector search = {
    .type = 977, .version = 0, .name = "AzureSearchQueryKey", .custom_name = "",
    .description = "Azure Search Query Keys are used to authenticate search requests to Azure Search service. They should be kept confidential to prevent unauthorized access to search indexes and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_search,
};

int br_azuresearchquerykey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Azure Search query detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-zA-Z]{52})\\b", &patterns.key, error) != 0) return -1;
    if (!patterns.url && br_regex_compile_prefixed(keywords, 1,
        "https://([0-9a-z]{5,40})\\.search\\.windows\\.net/indexes/([0-9a-z]{5,40})\\b", &patterns.url, error) != 0) return -1;
    if (!patterns.canonical && br_regex_compile(
        "^https://[0-9a-z]{5,40}\\.search\\.windows\\.net/indexes/[0-9a-z]{5,40}$", &patterns.canonical, error) != 0) return -1;
    *out = &search;
    return 0;
}
