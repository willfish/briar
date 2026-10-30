/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * WalkScore, from pinned TruffleHog pkg/detectors/walkscore/walkscore.go.
 * A successful response is verified only when its body contains "distance".
 * A body read error drops the candidate; a transport error still publishes it.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!body.data || body.len < n) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[160];
    int n = snprintf(url, sizeof(url),
                     "https://transit.walkscore.com/transit/search/stops/?lat=47.6101359&lon=-122.3420567&wsapikey=%s",
                     key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format WalkScore URL");
    if (!ctx) return 1;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .timeout_ms = 5000, .detector_type = 475, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int outcome = 0;
    if (!sent && response.body_error) outcome = 1;
    else if (!sent && response.status >= 200 && response.status < 300 && contains(response.body, "distance"))
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid WalkScore scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key(&result, detector->type, found.items[i], "key") != 0)
            rc = fail(&owned, "cannot create WalkScore finding");
        else if (verify_requested && (outcome = verify(ctx, found.items[i], &result, &owned)) < 0)
            rc = -1;
        else if (!outcome && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append WalkScore finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "WalkScore", .type = 475, .description =
        "Walkscore API keys can be used to access Walkscore's services for retrieving walkability scores and related data.",
    .keywords = (const char *[]){"walkscore", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_walkscore_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WalkScore detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
