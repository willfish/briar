/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/surveysparrow/surveysparrow.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_surveysparrow(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[103];
    int an = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (an != 95) return;
    const br_header headers[] = {
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.surveysparrow.com/v1/contacts", .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 202,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* TrimSpace is a no-op for this capture alphabet. Transport errors are suppressed. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_surveysparrow(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid SurveySparrow scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len != 88) rc = fail(&owned, "invalid SurveySparrow capture");
        else if (br_finding_key_bytes(&result, 202, key, "key") != 0)
            rc = fail(&owned, "cannot create SurveySparrow result");
        else if (verify) {
            /* Complete the URL before NewRequestWithContext's nil-context skip. */
            if (!ctx) skip = true;
            else verify_surveysparrow(ctx, keys.items[i], &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append SurveySparrow result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"surveysparrow"};
static br_detector surveysparrow = {
    .type = 202, .version = 0, .name = "SurveySparrow", .custom_name = "",
    .description = "SurveySparrow is a survey platform for collecting feedback and data. The detected key can be used to access and manage surveys and responses.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_surveysparrow,
};

int br_surveysparrow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SurveySparrow detector output");
    *out = NULL;
    if (br_key_pattern_init(&surveysparrow, "\\b([a-zA-Z0-9-_]{88})\\b", error) != 0) return -1;
    *out = &surveysparrow;
    return 0;
}
