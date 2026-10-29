/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/helpcrunch/helpcrunch.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { HELPCRUNCH_ABORT = -1, HELPCRUNCH_KEEP = 0, HELPCRUNCH_SKIP = 1 } helpcrunch_outcome;

static int helpcrunch_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static helpcrunch_outcome helpcrunch_verify(const br_scan_ctx *ctx, br_slice key,
                                            br_result *result, char **error)
{
    /* NewRequestWithContext precedes Bearer assembly. A nil context drops only
     * this candidate, after its finding has already been constructed. */
    if (!ctx) return HELPCRUNCH_SKIP;
    char authorization[336];
    if (key.len != 328 || key.len > sizeof(authorization) - sizeof("Bearer ")) {
        helpcrunch_fail(error, "cannot construct HelpCrunch Authorization");
        return HELPCRUNCH_ABORT;
    }
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.helpcrunch.com/v1/departments",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses every Do error and never reads the body. Shared ABI1
     * preparation failures inhabit that same suppressed send domain. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Keep original auth/key/URL alive through release, even on setup failure.
     * Synthesized headers/UA end at send return. Source instead defers Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return HELPCRUNCH_KEEP;
}

static int helpcrunch_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return helpcrunch_fail(error, "invalid or uninitialized HelpCrunch scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* FindAll preserves occurrences and duplicates. TrimSpace is a no-op on
     * this ASCII alphabet; no JWT/Base64, entropy or whole-token validation. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        helpcrunch_outcome outcome = HELPCRUNCH_KEEP;
        if (key.len != 328) {
            helpcrunch_fail(&owned_error, "invalid HelpCrunch capture");
            outcome = HELPCRUNCH_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            helpcrunch_fail(&owned_error, "cannot create HelpCrunch result");
            outcome = HELPCRUNCH_ABORT;
        } else if (verify) {
            outcome = helpcrunch_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == HELPCRUNCH_KEEP && br_results_push(out, &result) != 0) {
            helpcrunch_fail(&owned_error, "cannot append HelpCrunch result");
            outcome = HELPCRUNCH_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HELPCRUNCH_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const helpcrunch_keywords[] = {"helpcrunch"};
static br_detector helpcrunch_detector = {
    .type = 164, .version = 0, .name = "HelpCrunch", .custom_name = "",
    .description = "HelpCrunch is a customer communication platform offering live chat, email automation, and more. HelpCrunch API keys can be used to access and manage customer interactions and data.",
    .keywords = helpcrunch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = helpcrunch_scan,
};

int br_helpcrunch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return helpcrunch_fail(error, "invalid HelpCrunch detector output");
    *out = NULL;
    if (br_key_pattern_init(&helpcrunch_detector, "\\b([a-zA-Z-0-9+/=]{328})", error) != 0)
        return -1;
    *out = &helpcrunch_detector;
    return 0;
}
