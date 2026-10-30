/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pagerdutyapikey/pagerdutyapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pager_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    /* NULL is a checked no-op. +1 is fatal and must not release again. */
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return pager_fail(error, "cannot record PagerDutyApiKey verification error");
    return 0;
}

/* Close is inside this helper, before the setter and before publication.
 * Do not defer it until scan return. The stack header array is not retained.
 * The owned Authorization value stays alive through send and this release. */
static int pager_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return set_cause(result, "net/http: nil Context", key, error);
    char *authorization = malloc(sizeof("Token ") + key.len);
    if (!authorization) return pager_fail(error, "cannot allocate PagerDutyApiKey authorization");
    memcpy(authorization, "Token ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/vnd.pagerduty+json;version=2"},
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.pagerduty.com/users",
        .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        int stored = br_result_set_verification_error(result, send_error, &key, 1);
        free(send_error);
        if (stored != 0) return pager_fail(error, "cannot record PagerDutyApiKey verification error");
        return 0;
    }
    free(send_error);
    const char *cause = NULL;
    char status_error[64];
    _Static_assert(sizeof(status_error) >= sizeof("unexpected HTTP response status -2147483648"),
                   "PagerDuty status cause must hold every int");
    int status = response.status;
    if (status == 200 || status == 403 || status == 402)
        result->verified = true;
    else if (status == 401 || status == 400 || status == 404)
        result->verified = false;
    else if (status == 429)
        cause = "PagerDuty rate limit reached";
    else {
        int formatted = snprintf(status_error, sizeof(status_error),
                                 "unexpected HTTP response status %d", status);
        if (formatted < 0 || (size_t)formatted >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(authorization);
            return pager_fail(error, "cannot format PagerDutyApiKey status");
        }
        cause = status_error;
    }
    /* Verdict is already decided. One release, then the setter, including nil. */
    br_http_release(ctx, &response);
    free(authorization);
    return set_cause(result, cause, key, error);
}

static int pager_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pager_fail(error, "invalid or uninitialized PagerDutyApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* TrimSpace is a no-op. Keep every duplicate. Finding resources precede
     * the nil-context setter. The client field is not a setter; verification
     * uses the scan transport. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 20)
            rc = pager_fail(&owned_error, "invalid PagerDutyApiKey capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pager_fail(&owned_error, "cannot create PagerDutyApiKey result");
        else if (verify)
            rc = pager_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pager_fail(&owned_error, "cannot append PagerDutyApiKey result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pager_keywords[] = {"pagerduty", "pager_duty", "pd_", "pd-"};
static br_detector pager_detector = {
    .type = 32, .version = 0, .name = "PagerDutyApiKey", .custom_name = "",
    .description = "PagerDuty is an incident management platform that provides reliable notifications, automatic escalations, on-call scheduling, and other functionality to help teams detect and fix infrastructure problems quickly. PagerDuty API keys can be used to access and manage these functionalities.",
    .keywords = pager_keywords, .nkeywords = 4,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pager_scan,
};

int br_pagerdutyapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pager_fail(error, "invalid PagerDutyApiKey detector output");
    *out = NULL;
    if (!pager_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(pager_keywords, 4, "\\b(u\\+[a-zA-Z0-9_+-]{18})\\b",
                                      &regex, error) != 0)
            return -1;
        pager_detector.state = regex;
    }
    *out = &pager_detector;
    return 0;
}
