/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/posthog/posthog.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char posthog_pattern[] = "\\b(phx_[a-zA-Z0-9_]{43,48})\\b";
static const char posthog_us_prefix[] = "https://app.posthog.com/api/event/?personal_api_key=";
static const char posthog_eu_prefix[] = "https://eu.posthog.com/api/event/?personal_api_key=";
_Static_assert(sizeof(posthog_us_prefix) - 1 == 52, "PostHog US prefix is 52 bytes");
_Static_assert(sizeof(posthog_eu_prefix) - 1 == 51, "PostHog EU prefix is 51 bytes");

static int posthog_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int posthog_url(const char *prefix, size_t prefix_len, br_slice key, char **out, char **error)
{
    /* Raw concatenation, not URL escaping. The capture class needs none. */
    if (out) *out = NULL;
    if (!out || !prefix || strlen(prefix) != prefix_len || (prefix_len != 52 && prefix_len != 51) ||
        !key.data || !key.len || key.len > SIZE_MAX - prefix_len)
        return posthog_fail(error, "invalid PostHog key or URL prefix");
    size_t len = prefix_len + key.len;
    if (len > INT_MAX) return posthog_fail(error, "PostHog URL exceeds formatter capacity");
    char *url = malloc(len + 1);
    if (!url) return posthog_fail(error, "cannot allocate PostHog URL");
    int n = snprintf(url, len + 1, "%s%.*s", prefix, (int)key.len, (const char *)key.data);
    /* Every count other than the complete URL is owned failure, including +1. */
    if (n < 0 || (size_t)n != len) {
        free(url);
        return posthog_fail(error, "cannot format PostHog URL");
    }
    *out = url;
    return 0;
}

static int posthog_verify(const br_scan_ctx *ctx, br_slice key, bool *verified, bool *drop, char **error)
{
    char *us = NULL, *eu = NULL;
    *drop = false;
    /* Both exact URLs before nil handling. A failed build still attempts the other.
     * Preserve the first owned error; this is not the ordinary constructor drop. */
    int us_rc = posthog_url(posthog_us_prefix, sizeof(posthog_us_prefix) - 1, key, &us, error);
    int eu_rc = posthog_url(posthog_eu_prefix, sizeof(posthog_eu_prefix) - 1, key, &eu, error);
    int rc = 0;
    if (us_rc != 0 || eu_rc != 0) rc = -1;
    else if (!ctx) *drop = true;
    else {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        br_http_request request = {
            .method = "GET", .url = us, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = 161,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        int sent = br_http_send(ctx, &request, &response, &send_error);
        /* Body bytes and body_error are never read. Nonzero US Do does not
         * inspect status, so a leftover 401 cannot reach EU. */
        bool call_eu = false;
        if (sent == 0 && response.status >= 200 && response.status < 300) *verified = true;
        else if (sent == 0 && response.status == 401) call_eu = true;
        /* Release this attempted send before EU. That is the explicit C
         * scheduling gap, not source deferred-close equivalence. */
        br_http_release(ctx, &response);
        free(send_error);
        if (call_eu) {
            request.url = eu;
            response = (br_http_response){0};
            send_error = NULL;
            sent = br_http_send(ctx, &request, &response, &send_error);
            if (sent == 0 && response.status >= 200 && response.status < 300) *verified = true;
            br_http_release(ctx, &response);
            free(send_error);
        }
    }
    free(us);
    free(eu);
    return rc;
}

static int posthog_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return posthog_fail(error, "invalid or uninitialized PostHog scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Raw regex, not PrefixRegex. All occurrences in order, duplicates kept.
     * The capture class makes source TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool drop = false;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = posthog_fail(&owned_error, "cannot create PostHog finding");
        if (rc == 0 && verify)
            rc = posthog_verify(ctx, key, &result.verified, &drop, &owned_error);
        if (rc == 0 && drop) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = posthog_fail(&owned_error, "cannot append PostHog finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        posthog_fail(&owned_error, "cannot collect PostHog credentials");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const posthog_keywords[] = {"phx_"};
static br_detector posthog_detector = {
    .type = 161, .version = 0, .name = "PosthogApp", .custom_name = "",
    .description = "PostHog is an open-source product analytics platform. The phx_ keys are used to authenticate and track events in PostHog.",
    .keywords = posthog_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = posthog_scan,
};

int br_posthog_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return posthog_fail(error, "invalid PostHog detector output");
    *out = NULL;
    if (!posthog_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile(posthog_pattern, &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        posthog_detector.state = pattern;
    }
    *out = &posthog_detector;
    return 0;
}
