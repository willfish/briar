/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clearbit/clearbit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int clearbit_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void clearbit_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[43]; /* Bearer + SPACE + 35 captured ASCII bytes + NUL. */
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 35);
    authorization[42] = 0;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://person.clearbit.com/v1/people/email/alex@alexmaccaw.com",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 334,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire adapter/Do nonzero domain, including setup/allocation
     * failures ABI1 cannot distinguish. Do not infer stages from error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only. ABI1 eagerly buffers and releases per
     * request; that lifecycle gap remains. Bodies/read errors are ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int clearbit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return clearbit_fail(error, "invalid or uninitialized Clearbit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII headers are otherwise constructor-safe.
         * Known nil-context construction failure skips verify candidates only. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; endpoint underscores are captured word bytes. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = clearbit_fail(error, "out of memory creating Clearbit result");
        else if (verify) clearbit_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = clearbit_fail(error, "out of memory appending Clearbit result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const clearbit_keywords[] = {"clearbit"};
static br_detector clearbit_detector = {
    .type = 334, .version = 0, .name = "Clearbit", .custom_name = "",
    .description = "Clearbit provides powerful APIs for enriching data about companies and people. "
                   "Clearbit API keys can be used to access and retrieve detailed information about these entities.",
    .keywords = clearbit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = clearbit_scan,
};

int br_clearbit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return clearbit_fail(error, "invalid Clearbit detector output");
    *out = NULL;
    if (br_key_pattern_init(&clearbit_detector, "\\b([0-9a-z_]{35})\\b", error) != 0) return -1;
    *out = &clearbit_detector;
    return 0;
}
