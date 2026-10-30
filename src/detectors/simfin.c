/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/simfin/simfin.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SIMFIN_ABORT = -1, SIMFIN_KEEP = 0, SIMFIN_SKIP = 1 } simfin_outcome;

static int simfin_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static simfin_outcome simfin_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                    char **error)
{
    char url[sizeof("https://simfin.com/api/v2/companies/list?api-key=") + 32];
    int n = snprintf(url, sizeof(url), "https://simfin.com/api/v2/companies/list?api-key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        simfin_fail(error, "cannot format SimFin URL");
        return SIMFIN_ABORT;
    }
    if (!ctx) return SIMFIN_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    simfin_outcome outcome = SIMFIN_KEEP;
    /* Do errors stay unverified and still publish. ReadAll errors continue,
     * dropping only this occurrence. `"error"` anywhere blocks verification. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error) outcome = SIMFIN_SKIP;
        else {
            static const unsigned char marker[] = "\"error\"";
            bool bad = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && !bad;
        }
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int simfin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return simfin_fail(error, "invalid or uninitialized SimFin scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        simfin_outcome outcome = SIMFIN_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            simfin_fail(&owned_error, "cannot create SimFin result");
            outcome = SIMFIN_ABORT;
        } else if (verify)
            outcome = simfin_verify(ctx, key, &result, &owned_error);
        if (outcome == SIMFIN_ABORT) rc = -1;
        else if (outcome == SIMFIN_KEEP && br_results_push(out, &result) != 0) {
            simfin_fail(&owned_error, "cannot append SimFin result");
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

static const char *const simfin_keywords[] = {"simfin"};
static br_detector simfin_detector = {
    .type = 851, .version = 0, .name = "SimFin", .custom_name = "",
    .description = "SimFin provides financial data and APIs for accessing this data. "
                   "SimFin API keys can be used to access and retrieve financial data.",
    .keywords = simfin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = simfin_scan,
};

int br_simfin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return simfin_fail(error, "invalid SimFin detector output");
    *out = NULL;
    if (br_key_pattern_init(&simfin_detector, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &simfin_detector;
    return 0;
}
