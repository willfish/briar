/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/optimizely/optimizely.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { OPT_ABORT = -1, OPT_KEEP = 0, OPT_SKIP = 1 } optimizely_outcome;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static optimizely_outcome verify_optimizely(const br_scan_ctx *ctx, const char *key,
                                            br_result *result, char **error)
{
    /* Static URL. Authorization is added only after NewRequestWithContext. */
    if (!ctx) return OPT_SKIP;
    char authorization[8 + 54 + 1];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) {
        fail(error, "cannot format Optimizely authorization");
        return OPT_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.optimizely.com/v2/projects",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return OPT_KEEP;
}

static int scan_optimizely(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Optimizely scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        optimizely_outcome outcome = OPT_KEEP;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key")) {
            fail(&owned_error, "cannot create Optimizely result");
            outcome = OPT_ABORT;
        } else if (verify)
            outcome = verify_optimizely(ctx, keys.items[i], &result, &owned_error);
        if (outcome == OPT_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Optimizely result");
            outcome = OPT_ABORT;
        }
        br_result_clear(&result);
        if (outcome == OPT_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"optimizely"};
static br_detector optimizely = {
    .type = 595, .version = 0, .name = "Optimizely", .custom_name = "",
    .description = "Optimizely is a platform for A/B testing and feature flagging. Optimizely API keys can be used to manage and access these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_optimizely,
};

int br_optimizely_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Optimizely detector output");
    *out = NULL;
    if (br_key_pattern_init(&optimizely, "\\b([0-9A-Za-z-:]{54})\\b", error)) return -1;
    *out = &optimizely;
    return 0;
}
