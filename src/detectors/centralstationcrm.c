/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/centralstationcrm/centralstationcrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_centralstationcrm(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"X-Apikey", key}}; /* Go Header.Add canonicalizes X-apikey. */
    const br_http_request request = {.method = "GET", .url = "https://api.centralstationcrm.net/api/users.json",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 318};
    br_http_response response = {0};
    char *error = NULL;
    /* All Do errors are suppressed. ABI1 also mixes adapter allocation/setup
     * failures into this nonzero domain; never infer their stage from text. */
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close-only until scan return without draining. ABI1 may
     * already have buffered the body and releases per request instead. */
    br_http_release(ctx, &response);
    free(error);
}

static int scan_centralstationcrm(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                  br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CentralStationCRM scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the known
         * constructor failure. Source skips the candidate, not the invocation. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Captured ASCII alphanumeric bytes make source TrimSpace a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating CentralStationCRM result");
        else if (verify) verify_centralstationcrm(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending CentralStationCRM result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"centralstationcrm"};
static const char *const extraction_prefix[] = {"centralstation"};
static br_detector centralstationcrm = {
    .type = 318, .version = 0, .name = "CentralStationCRM", .custom_name = "",
    .description = "CentralStationCRM is a customer relationship management service. The API keys can be used to access and manage customer data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_centralstationcrm,
};

int br_centralstationcrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CentralStationCRM detector output");
    *out = NULL;
    if (!centralstationcrm.state) {
        br_regex *pattern = NULL;
        /* Dispatch uses the full name; extraction uses the shorter prefix.
         * A following literal crm consumes three of the 40 gap runes. */
        if (br_regex_compile_prefixed(extraction_prefix, 1, "\\b([a-z0-9]{30})\\b", &pattern, error) != 0)
            return -1;
        centralstationcrm.state = pattern;
    }
    *out = &centralstationcrm;
    return 0;
}
