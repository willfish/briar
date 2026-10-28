/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/grafana/grafana.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int grafana_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int grafana_verify(const br_scan_ctx *ctx, br_slice key,
                          br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &key, 1) != 0)
            return grafana_fail(error, "cannot store Grafana verification error");
        return 0;
    }
    /* The fixed URL's constructor precedes auth. The grammar bounds the whole
     * credential, not a truncated prefix; only this original value survives send. */
    char authorization[7 + 167 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://grafana.com/api/v1/tokens?region=us",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *read_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    bool verified = false;
    int rc = 0;
    /* Retain the entire mixed setup/Do error domain without text classification. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: case 403: verified = true; break;
        case 401:
            if (response.body_error) {
                /* Borrowed causes, even empty ones, must outlive drain/Close. */
                read_error = strdup(response.body_error);
                if (!read_error) rc = grafana_fail(error, "cannot copy Grafana read error");
                else cause = read_error;
            } else {
                static const unsigned char permission[] = "invalid permission";
                static const unsigned char scope[] = "required scope";
                verified = br_slice_find(response.body, (br_slice){permission, sizeof(permission) - 1}, 0) != SIZE_MAX ||
                           br_slice_find(response.body, (br_slice){scope, sizeof(scope) - 1}, 0) != SIZE_MAX;
            }
            break;
        default: {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = grafana_fail(error, "cannot format Grafana status error");
            else cause = status_error;
            break;
        }
        }
    }
    /* Source helper's deferred drain/Close finishes before FromData publishes
     * Verified or calls the checked full-key-redacting setter (also on NULL). */
    br_http_release(ctx, &response);
    if (rc == 0) {
        result->verified = verified;
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = grafana_fail(error, "cannot store Grafana verification error");
    }
    free(read_error);
    free(send_error);
    return rc;
}

static int grafana_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return grafana_fail(error, "invalid or uninitialized Grafana scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace cannot change this alphabet. Preserve every occurrence,
         * including duplicates, and construct the finding before verification. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = grafana_fail(&owned_error, "cannot create Grafana result");
        if (rc == 0 && verify) rc = grafana_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = grafana_fail(&owned_error, "cannot append Grafana result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const grafana_keywords[] = {"glc_eyJ"};
static br_detector grafana_detector = {
    .type = 830, .version = 0, .name = "Grafana", .custom_name = "",
    .description = "Grafana is an open-source platform for monitoring and observability. Grafana API keys can be used to access and manage Grafana resources.",
    .keywords = grafana_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = grafana_scan,
};

int br_grafana_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return grafana_fail(error, "invalid Grafana detector output");
    *out = NULL;
    if (!grafana_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(glc_eyJ[A-Za-z0-9+\\/=]{60,160})", &regex, error) != 0)
            return -1;
        grafana_detector.state = regex;
    }
    *out = &grafana_detector;
    return 0;
}
