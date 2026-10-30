/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tmetric/tmetric.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { TM_ABORT = -1, TM_KEEP = 0, TM_DROP = 1 } tm_outcome;

static int tm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static tm_outcome tm_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return TM_DROP;
    if (key.len != 64) return tm_fail(error, "unexpected Tmetric key length"), TM_ABORT;
    char authorization[7 + 64 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 64);
    authorization[71] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.tmetric.com/api/v3/user",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return TM_KEEP;
}

static int tm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tm_fail(error, "invalid or uninitialized Tmetric scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        tm_outcome outcome = TM_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = tm_fail(&owned_error, "cannot create Tmetric result");
        else if (verify)
            outcome = tm_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && outcome == TM_ABORT) rc = -1;
        if (rc == 0 && outcome == TM_KEEP && br_results_push(out, &result) != 0)
            rc = tm_fail(&owned_error, "cannot append Tmetric result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tm_keywords[] = {"tmetric"};
static br_detector tm_detector = {
    .type = 446, .version = 0, .name = "Tmetric", .custom_name = "",
    .description = "Tmetric is a time tracking service. Tmetric API keys can be used to access and manage time tracking data.",
    .keywords = tm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tm_scan,
};

int br_tmetric_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tm_fail(error, "invalid Tmetric detector output");
    *out = NULL;
    if (br_key_pattern_init(&tm_detector, "\\b([0-9A-Z]{64})\\b", error) != 0) return -1;
    *out = &tm_detector;
    return 0;
}
