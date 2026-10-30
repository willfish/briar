/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/survicate/survicate.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SURVICATE_ABORT = -1, SURVICATE_KEEP = 0, SURVICATE_SKIP = 1 } survicate_outcome;

static int survicate_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static survicate_outcome survicate_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                          char **error)
{
    /* Go uses fmt.Sprintf("Basic %s", key) with no further encoding. */
    char authorization[sizeof("Basic ") + 32];
    int n = snprintf(authorization, sizeof(authorization), "Basic %.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(authorization)) {
        survicate_fail(error, "cannot format Survicate authorization");
        return SURVICATE_ABORT;
    }
    if (!ctx) return SURVICATE_SKIP;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://data-api.survicate.com/v1/surveys",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return SURVICATE_KEEP;
}

static int survicate_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return survicate_fail(error, "invalid or uninitialized Survicate scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        survicate_outcome outcome = SURVICATE_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            survicate_fail(&owned_error, "cannot create Survicate result");
            outcome = SURVICATE_ABORT;
        } else if (verify)
            outcome = survicate_verify(ctx, key, &result, &owned_error);
        if (outcome == SURVICATE_ABORT) rc = -1;
        else if (outcome == SURVICATE_KEEP && br_results_push(out, &result) != 0) {
            survicate_fail(&owned_error, "cannot append Survicate result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const survicate_keywords[] = {"survicate"};
static br_detector survicate_detector = {
    .type = 204, .version = 0, .name = "Survicate", .custom_name = "",
    .description = "Survicate is a survey platform that allows users to collect feedback and insights "
                   "from customers. Survicate API keys can be used to access and manage surveys and responses.",
    .keywords = survicate_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = survicate_scan,
};

int br_survicate_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return survicate_fail(error, "invalid Survicate detector output");
    *out = NULL;
    if (br_key_pattern_init(&survicate_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &survicate_detector;
    return 0;
}
