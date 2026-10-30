/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/prospectcrm/prospectcrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

enum { PROSPECT_KEEP = 0, PROSPECT_DROP = 1, PROSPECT_FATAL = -1 };

static int prospect_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return PROSPECT_FATAL;
}

static int prospect_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 32) return PROSPECT_FATAL;
    /* Nil context is the constructor failure and drops this candidate before
     * Authorization is assembled. */
    if (!ctx) return PROSPECT_DROP;
    char authorization[7 + 32 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 32);
    authorization[39] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api-batch-v1.prospect365.com/Contacts",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return PROSPECT_KEEP;
}

static int prospect_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return prospect_fail(error, "invalid or uninitialized ProspectCRM scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        int outcome = PROSPECT_KEEP;
        /* TrimSpace is a no-op. Duplicates remain. Finding precedes the skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            outcome = prospect_fail(&owned_error, "cannot create ProspectCRM result");
        else if (verify)
            outcome = prospect_verify(ctx, key, &result);
        if (outcome == PROSPECT_FATAL) rc = -1;
        if (outcome == PROSPECT_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = prospect_fail(&owned_error, "cannot append ProspectCRM result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

/* Keywords prefilter on prospectcrm. The pattern prefix is only "prospect". */
static const char *const prospect_keywords[] = {"prospectcrm"};
static const char *const prospect_prefix[] = {"prospect"};
static br_detector prospect_detector = {
    .type = 275, .version = 0, .name = "ProspectCRM", .custom_name = "",
    .description = "ProspectCRM is a customer relationship management system. The API keys can be used to access and manage customer data within ProspectCRM.",
    .keywords = prospect_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = prospect_scan,
};

int br_prospectcrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return prospect_fail(error, "invalid ProspectCRM detector output");
    *out = NULL;
    if (!prospect_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(prospect_prefix, 1, "\\b([a-z0-9-]{32})\\b", &regex, error) != 0)
            return -1;
        prospect_detector.state = regex;
    }
    *out = &prospect_detector;
    return 0;
}
