/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/revampcrm/revampcrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum { REV_ABORT = -1, REV_KEEP = 0, REV_SKIP = 1 } rev_outcome;

static int rev_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static rev_outcome rev_verify(const br_scan_ctx *ctx, br_slice id, br_slice token,
                              br_result *result, char **error)
{
    /* SetBasicAuth is after NewRequestWithContext. Nil context drops this
     * pair before encoding. Encoding failure is fatal. The id is the username
     * and the token is the password. The fixed URL cannot fail to parse. */
    if (!ctx) return REV_SKIP;
    char *authorization = NULL;
    if (br_http_basic_auth(id, token, &authorization, error) != 0) {
        free(authorization);
        return REV_ABORT;
    }
    rev_outcome outcome = REV_KEEP;
    {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://app.revampcrm.com/api/1.0/User/WhoAmI",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Do failures stay unverified with no setter. Body and read errors
         * are ignored. Only 2xx verifies. */
        if (br_http_send(ctx, &request, &response, &transport_error) == 0)
            result->verified = response.status >= 200 && response.status < 300;
        br_http_release(ctx, &response);
        free(transport_error);
    }
    free(authorization);
    return outcome;
}

static int rev_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return rev_fail(error, "invalid or uninitialized RevampCRM scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures tokens = {0}, ids = {0};
    char *owned_error = NULL;
    /* Prefix is revamp, not the keyword revampcrm. Ordered duplicates stay.
     * Every token is paired with every id. The finding stores only the token. */
    int rc = br_captures_find(patterns[0], input, &tokens, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &ids, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        if (token.len != 40) {
            rev_fail(&owned_error, "invalid RevampCRM token capture");
            rc = -1;
            break;
        }
        for (size_t j = 0; j < ids.len; ++j) {
            br_slice id = br_captures_at(&ids, j);
            br_result result = {0};
            rev_outcome outcome = REV_KEEP;
            if (id.len < 25 || id.len > 30) {
                rev_fail(&owned_error, "invalid RevampCRM id capture");
                outcome = REV_ABORT;
            } else if (br_finding_key_bytes(&result, detector->type, token, "key") != 0) {
                rev_fail(&owned_error, "cannot create RevampCRM result");
                outcome = REV_ABORT;
            } else if (verify) {
                outcome = rev_verify(ctx, id, token, &result, &owned_error);
            }
            if (outcome == REV_KEEP && br_results_push(out, &result) != 0) {
                rev_fail(&owned_error, "cannot append RevampCRM result");
                outcome = REV_ABORT;
            }
            br_result_clear(&result);
            if (outcome == REV_ABORT) {
                rc = -1;
                break;
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rev_keywords[] = {"revampcrm"};
static br_regex *rev_patterns[2];
static br_detector rev_detector = {
    .type = 299, .version = 0, .name = "RevampCRM", .custom_name = "",
    .description = "RevampCRM is a customer relationship management service. The credentials can be used to access and manage customer data.",
    .keywords = rev_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = rev_scan, .state = rev_patterns,
};

int br_revampcrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rev_fail(error, "invalid RevampCRM detector output");
    *out = NULL;
    if (!rev_patterns[0]) {
        const char *const prefix[] = {"revamp"};
        if (br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9]{40}\\b)", &rev_patterns[0], error) != 0 ||
            br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9.-@]{25,30})\\b", &rev_patterns[1], error) != 0)
            return -1;
    }
    *out = &rev_detector;
    return 0;
}
