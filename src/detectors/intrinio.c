/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/intrinio/intrinio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int intrinio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int intrinio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, char **error)
{
    static const char prefix[] = "https://api-v2.intrinio.com/securities?api_key=";
    if (key.len > SIZE_MAX - sizeof(prefix))
        return intrinio_fail(error, "Intrinio verification URL too large");
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return intrinio_fail(error, "cannot allocate Intrinio verification URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The full literal URL is constructed before NewRequestWithContext's
     * nil-context drop. Alphanumeric captures require no URL escaping. */
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole mixed shared setup/Do failure domain. The source
     * ignores all bodies/read errors and never sets a verification error. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* URL and captures survive ordinary release; synthesized effective
     * request/headers/UA survive only send return. This eager release does not
     * reproduce source deferred Close timing or body draining. */
    free(send_error);
    free(url);
    return 0;
}

static int intrinio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return intrinio_fail(error, "invalid or uninitialized Intrinio scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op on this alphabet. Keep original occurrences
         * and duplicates, with no detector-local filtering or cleaning. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = intrinio_fail(&owned_error, "cannot create Intrinio finding");
        if (rc == 0 && verify)
            rc = intrinio_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = intrinio_fail(&owned_error, "cannot append Intrinio finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const intrinio_keywords[] = {"intrinio"};
static br_detector intrinio_detector = {
    .type = 579, .version = 0, .name = "Intrinio", .custom_name = "",
    .description = "Intrinio provides financial data APIs. Intrinio API keys can be used to access various financial datasets and services.",
    .keywords = intrinio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = intrinio_scan,
};

int br_intrinio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return intrinio_fail(error, "invalid Intrinio detector output");
    *out = NULL;
    if (!intrinio_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(intrinio_keywords, 1,
                "\\b([a-zA-Z0-9]{44})\\b", &regex, error) != 0)
            return -1;
        intrinio_detector.state = regex;
    }
    *out = &intrinio_detector;
    return 0;
}
