/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/semaphore/semaphore.go.
 * The engine keyword is semaphore.co; the capture prefix is semaphore. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *key_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool has_digit(const char *key)
{
    for (const char *p = key; *p; ++p)
        if (*p >= '0' && *p <= '9') return true;
    return false;
}

static int verify_semaphore(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[96];
    int n = snprintf(url, sizeof(url), "https://api.semaphore.co/api/v4/account?apikey=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format Semaphore URL");
    if (!ctx) return 1;
    const br_header headers[] = {{"Accept", "application/vnd.semaphore+json; version=3"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    free(transport_error);
    if (!rc && response.body_error) {
        br_http_release(ctx, &response);
        return 1; /* A body read error drops this candidate. */
    }
    if (!rc && response.status >= 200 && response.status < 300) {
        br_slice needle = {(const unsigned char *)"account_id", 10};
        if (br_slice_find(response.body, needle, 0) != SIZE_MAX) result->verified = true;
    }
    br_http_release(ctx, &response);
    return 0;
}

static int scan_semaphore(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Semaphore scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        if (!has_digit(keys.items[i])) continue;
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create Semaphore result");
            outcome = -1;
        } else if (verify)
            outcome = verify_semaphore(ctx, keys.items[i], &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Semaphore result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"semaphore.co"};
static br_detector semaphore = {
    .type = 609, .version = 0, .name = "Semaphore", .custom_name = "",
    .description = "Semaphore is a hosted continuous integration and deployment service used to automate software development workflows. Semaphore API keys can be used to access and manage CI/CD pipelines.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_semaphore,
};

int br_semaphore_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"semaphore"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Semaphore detector output");
    *out = NULL;
    if (!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-z]{32})\\b", &key_re, error) != 0)
        return -1;
    semaphore.state = key_re;
    *out = &semaphore;
    return 0;
}
