/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azuresearchadminkey/azuresearchadminkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *service; } search_admin_patterns;

static int search_admin_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int search_admin_verify(const br_scan_ctx *ctx, const char *key,
                                const char *service, br_result *result, char **error)
{
    char url[160]; /* The service capture contains at most 40 ASCII bytes. */
    snprintf(url, sizeof(url), "https://%s.search.windows.net/servicestats?api-version=2023-10-01-Preview", service);
    const br_header headers[] = {{"api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 976,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Source inspects only status; neither body contents nor read errors
         * participate in verification, including for rejected/error statuses. */
        if (response.status >= 200 && response.status < 300) result->verified = true;
        else if (response.status != 401 && response.status != 403) {
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    /* ABI ownership releases per request, rather than source's deferred Close. */
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) return search_admin_fail(error, "out of memory recording Azure Search Admin Key verification error");
    return 0;
}

static int search_admin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return search_admin_fail(error, "invalid Azure Search Admin Key scan arguments");
    const search_admin_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->service)
        return search_admin_fail(error, "uninitialized Azure Search Admin Key detector");
    /* NewRequestWithContext(nil, ...) fails and source skips each candidate.
     * Captured service names otherwise produce valid, ASCII-only URLs. */
    if (verify && !ctx) return 0;
    size_t original_len = out->len;
    br_captures keys = {0}, services = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->service, input, &services, false, error);
    /* TrimSpace is a no-op. Preserve every occurrence in key-major/service-minor
     * order, including duplicate products and all pairs following a success. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t s = 0; rc == 0 && s < services.len; ++s) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", services.items[s], "service") != 0)
                rc = search_admin_fail(error, "out of memory creating Azure Search Admin Key result");
            else if (verify) rc = search_admin_verify(ctx, keys.items[k], services.items[s], &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = search_admin_fail(error, "out of memory appending Azure Search Admin Key result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&services);
    return rc == 0 ? 0 : -1;
}

static search_admin_patterns search_admin_compiled;
static const char *const search_admin_keywords[] = {"azure"};
static const br_detector search_admin_detector = {
    .type = 976, .version = 0, .name = "AzureSearchAdminKey", .custom_name = "",
    .description = "Azure Search is a search-as-a-service solution that allows developers to incorporate search capabilities "
                   "into their applications. Azure Search Admin Keys can be used to manage and query search services.",
    .keywords = search_admin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &search_admin_compiled, .scan = search_admin_scan,
};

int br_azuresearchadminkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return search_admin_fail(error, "invalid Azure Search Admin Key detector output");
    *out = NULL;
    /* Prefix case folding is scoped to 'azure'; both source capture classes
     * explicitly allow mixed case, and their original spelling is retained. */
    if (!search_admin_compiled.key && br_regex_compile_prefixed(search_admin_keywords, 1,
        "\\b([0-9a-zA-Z]{52})\\b", &search_admin_compiled.key, error) != 0) return -1;
    if (!search_admin_compiled.service && br_regex_compile_prefixed(search_admin_keywords, 1,
        "\\b([0-9a-zA-Z]{7,40})\\b", &search_admin_compiled.service, error) != 0) return -1;
    *out = &search_admin_detector;
    return 0;
}
