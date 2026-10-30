/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/statuscake/statuscake.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { CAKE_ABORT = -1, CAKE_KEEP = 0, CAKE_SKIP = 1 } cake_outcome;

static int cake_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static cake_outcome cake_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* NewRequestWithContext fails before Header.Add. Nil context drops this
     * occurrence and is not a send. The fixed URL cannot fail to parse. */
    if (!ctx) return CAKE_SKIP;
    char authorization[7 + 20 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.statuscake.com/v1/ssl",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do failures stay unverified with no setter. Body and read errors are
     * ignored. Only 2xx verifies. The header stays live through release. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return CAKE_KEEP;
}

static int cake_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cake_fail(error, "invalid or uninitialized Statuscake scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        cake_outcome outcome = CAKE_KEEP;
        if (key.len != 20) {
            cake_fail(&owned_error, "invalid Statuscake capture");
            outcome = CAKE_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            cake_fail(&owned_error, "cannot create Statuscake result");
            outcome = CAKE_ABORT;
        } else if (verify) {
            outcome = cake_verify(ctx, key, &result);
        }
        if (outcome == CAKE_KEEP && br_results_push(out, &result) != 0) {
            cake_fail(&owned_error, "cannot append Statuscake result");
            outcome = CAKE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CAKE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const cake_keywords[] = {"statuscake"};
static br_detector cake_detector = {
    .type = 795, .version = 0, .name = "Statuscake", .custom_name = "",
    .description = "Statuscake is a website monitoring service. Statuscake API keys can be used to access and manage website monitoring configurations and data.",
    .keywords = cake_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cake_scan,
};

int br_statuscake_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cake_fail(error, "invalid Statuscake detector output");
    *out = NULL;
    if (br_key_pattern_init(&cake_detector, "\\b([a-zA-Z0-9]{20})\\b", error) != 0)
        return -1;
    *out = &cake_detector;
    return 0;
}
