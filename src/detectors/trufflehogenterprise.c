/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/trufflehogenterprise. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool line_contains(const unsigned char *line, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (n > len) return false;
    for (size_t i = 0; i + n <= len; ++i)
        if (!memcmp(line + i, needle, n)) return true;
    return false;
}

/* bufio.Scanner, 64 KiB token limit. A matching line wins before a later error. */
static int body_contains_data(br_slice body, const char *read_error, bool *found, char **cause)
{
    *found = false;
    size_t start = 0;
    for (size_t i = 0; i <= body.len; ++i) {
        if (i < body.len && body.data[i] != '\n') continue;
        size_t n = i - start;
        if (n && body.data[start + n - 1] == '\r') --n;
        if (n > 64 * 1024) {
            *cause = strdup("bufio.Scanner: token too long");
            return *cause ? 1 : -1;
        }
        if (line_contains(body.data + start, n, "data")) { *found = true; return 0; }
        start = i + 1;
    }
    if (read_error) {
        *cause = strdup(read_error);
        return *cause ? 1 : -1;
    }
    return 0;
}

static int verify_enterprise(const br_scan_ctx *ctx, const char *key, const char *secret,
                             const char *hostname, br_result *result, char **error)
{
    size_t host_len = strlen(hostname);
    if (host_len > SIZE_MAX - sizeof("https:///api/v1/sources"))
        return fail(error, "TruffleHog Enterprise URL is too large");
    size_t size = sizeof("https:///api/v1/sources") + host_len;
    char *url = malloc(size);
    if (!url) return fail(error, "cannot create TruffleHog Enterprise URL");
    snprintf(url, size, "https://%s/api/v1/sources", hostname);
    if (!ctx) { free(url); return 1; }
    const br_header headers[] = {
        {"Accept", "application/vnd.trufflehogenterprise+json; version=3"},
        {"X-Thog-Secret", secret},
        {"X-Thog-Key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 922,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    int rc = 0;
    if (sent == 0) {
        bool found = false;
        char *cause = NULL;
        int scanned = body_contains_data(response.body, response.body_error, &found, &cause);
        if (scanned < 0) rc = fail(error, "cannot read TruffleHog Enterprise response");
        else if (scanned > 0) {
            if (error && !*error) *error = cause;
            else free(cause);
            rc = -1; /* A scanner error aborts the whole invocation. */
        } else if (response.status >= 200 && response.status < 300 && found)
            result->verified = true;
    }
    br_http_release(ctx, &response);
    free(url);
    return rc;
}

static int scan_enterprise(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TruffleHog Enterprise scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0}, hosts = {0};
    int rc = br_captures_find(patterns[0], input, &keys, false, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &secrets, false, error);
    if (!rc) rc = br_captures_find(patterns[2], input, &hosts, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < secrets.len; ++j) {
            for (size_t k = 0; rc == 0 && k < hosts.len; ++k) {
                br_result result = {0};
                int drop = 0;
                if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
                    rc = fail(error, "out of memory creating TruffleHog Enterprise result");
                else if (verify)
                    drop = verify_enterprise(ctx, keys.items[i], secrets.items[j], hosts.items[k], &result, error);
                if (rc == 0 && drop < 0) rc = -1;
                else if (rc == 0 && drop == 0 && br_results_push(out, &result) != 0)
                    rc = fail(error, "cannot append TruffleHog Enterprise result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    br_captures_clear(&hosts);
    return rc == 0 ? 0 : -1;
}

static const char *const enterprise_keywords[] = {"thog"};
static br_regex *enterprise_patterns[3];
static br_detector enterprise_detector = {
    .type = 922, .version = 0, .name = "TrufflehogEnterprise", .custom_name = "",
    .description = "TruffleHog Enterprise is a tool for detecting and verifying secrets in your codebase. The keys and secrets detected can be used to access TruffleHog Enterprise services.",
    .keywords = enterprise_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = enterprise_patterns, .scan = scan_enterprise,
};

int br_trufflehogenterprise_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TruffleHog Enterprise detector output");
    *out = NULL;
    /* Source matches have no capture group; group 1 is the same full match. */
    if (!enterprise_patterns[0] &&
        br_regex_compile("\\b(thog-key-[0-9a-f]{16})\\b", &enterprise_patterns[0], error) != 0)
        return -1;
    if (!enterprise_patterns[1] &&
        br_regex_compile("\\b(thog-secret-[0-9a-f]{32})\\b", &enterprise_patterns[1], error) != 0)
        return -1;
    if (!enterprise_patterns[2] &&
        br_regex_compile("\\b([a-z]+-[a-z]+-[a-z]+\\.[a-z][0-9]\\.[a-z]+\\.trufflehog\\.org)\\b",
                         &enterprise_patterns[2], error) != 0)
        return -1;
    *out = &enterprise_detector;
    return 0;
}
