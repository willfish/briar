/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/calendarific/calendarific.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int calendarific_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void calendarific_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160]; /* Fixed URL plus exactly 32 captured ASCII alphanumeric bytes. */
    snprintf(url, sizeof(url), "https://calendarific.com/api/v2/holidays?&api_key=%s&country=US&year=2019", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 130,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ALL Client.Do errors are suppressed, not promoted to scan errors and not
     * interpreted as constructor failures. Body/read errors never participate. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close (without draining) until FromData returns. ABI1
     * releases per request and may have eagerly buffered the response body. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int calendarific_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return calendarific_fail(error, "invalid or uninitialized Calendarific scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the reachable
         * NewRequestWithContext failure. Source continues without a finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace changes nothing in the captured ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = calendarific_fail(error, "out of memory creating Calendarific result");
        else if (verify) calendarific_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = calendarific_fail(error, "out of memory appending Calendarific result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const calendarific_keywords[] = {"calendarific"};
static br_detector calendarific_detector = {
    .type = 130, .version = 0, .name = "Calendarific", .custom_name = "",
    .description = "Calendarific provides a public API for obtaining holiday information. "
                   "The API key can be used to access holiday data for various countries and years.",
    .keywords = calendarific_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = calendarific_scan,
};

int br_calendarific_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return calendarific_fail(error, "invalid Calendarific detector output");
    *out = NULL;
    if (br_key_pattern_init(&calendarific_detector, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &calendarific_detector;
    return 0;
}
