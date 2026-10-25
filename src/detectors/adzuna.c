/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/adzuna/adzuna.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } adzuna_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_adzuna(const br_scan_ctx *ctx, const char *key,
                         const char *id, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.adzuna.com/v1/api/jobs/us/search/1?app_id=%s&app_key=%s", id, key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 431,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream only inspects status, ignoring the body and body-read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream redacts the key, not the application ID. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_adzuna(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Adzuna scan arguments");
    const adzuna_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return fail(error, "uninitialized Adzuna detector");

    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, error);
    /* Both alphabets exclude whitespace, so upstream TrimSpace is a no-op.
     * Retain every occurrence, with keys outermost and IDs innermost. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                ids.items[i], "id") != 0 ||
                (verify && verify_adzuna(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating Adzuna result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static adzuna_patterns patterns;
static const char *const keywords[] = {"adzuna"};
static const br_detector adzuna = {
    .type = 431, .version = 0, .name = "Adzuna", .custom_name = "",
    .description = "Adzuna is a job search engine used to find job listings. "
                   "Adzuna API keys can be used to access job listing data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_adzuna,
};

int br_adzuna_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Adzuna detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{8})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &adzuna;
    return 0;
}
