/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nylas/nylas.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nylas_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int nylas_authorization(br_slice key, char value[38], char **error)
{
    if (!key.data || key.len != 30) return nylas_fail(error, "invalid Nylas token capture");
    int n = snprintf(value, 38, "Bearer %.*s", 30, (const char *)key.data);
    /* snprintf's ordinary return is a byte count. Every result other than the
     * COMPLETE 37 bytes is a fatal owned construction failure, including +1. */
    return n == 37 ? 0 : nylas_fail(error, "cannot format Nylas authorization");
}

static int nylas_verify(const br_scan_ctx *ctx, br_slice key, bool *verified, char **error)
{
    /* The fixed constructor's nil-context DROP was resolved by the caller.
     * Construct its bodyless request BEFORE ordered header/Authorization work. */
    br_http_request request = {
        .method = "GET", .url = "https://api.nylas.com/account",
        .profile = BR_HTTP_SANE, .detector_type = 617,
    };
    char bearer[38];
    br_header headers[] = {
        {"Accept", "application/vnd.nylas+json; version=3"},
        {"Authorization", NULL},
    };
    if (nylas_authorization(key, bearer, error) != 0) return -1;
    headers[1].value = bearer;
    request.headers = headers;
    request.nheaders = 2;
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    bool accepted = sent == 0 && response.status >= 200 && response.status < 300;
    /* WHOLE mixed preparation/Do error domain is ordinary false-kept. Bodies,
     * read errors and close results are irrelevant; NO setter on ANY path.
     * Keep ORIGINAL URL/key/Bearer/headers live through exactly one release;
     * ordinary synthesized header/UA storage ended at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    *verified = accepted;
    return 0;
}

static int nylas_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nylas_fail(error, "invalid or uninitialized Nylas scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* All full-match occurrences, IN ORDER and WITH duplicates, before findings.
     * Capture is ASCII alnum30, so the source TrimSpace is exactly a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nylas_fail(&owned_error, "cannot create Nylas finding");
        if (rc == 0 && verify) {
            /* Fixed valid URL/method: nil context is the constructor's only
             * reachable ordinary error. It DROPS this occurrence, not a cause. */
            if (!ctx) { br_result_clear(&result); continue; }
            rc = nylas_verify(ctx, key, &result.verified, &owned_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = nylas_fail(&owned_error, "cannot append Nylas finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        nylas_fail(&owned_error, "cannot collect Nylas tokens");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const nylas_keywords[] = {"nylas"};
static br_detector nylas_detector = {
    .type = 617, .version = 0, .name = "Nylas", .custom_name = "",
    .description = "Nylas is a platform providing email, calendar, and contacts APIs. Nylas API keys can be used to access and manage these services.",
    .keywords = nylas_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = nylas_scan,
};

int br_nylas_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nylas_fail(error, "invalid Nylas detector output");
    *out = NULL;
    if (!nylas_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(nylas_keywords, 1, "\\b([0-9A-Za-z]{30})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        nylas_detector.state = pattern;
    }
    *out = &nylas_detector;
    return 0;
}
