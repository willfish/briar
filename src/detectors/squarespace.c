/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/squarespace/squarespace.go. */
#include "detectors.h"
#include "captures.h"
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

static int verify_squarespace(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return 1;
    char authorization[80];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return fail(error, "cannot format Squarespace authorization");
    const br_header headers[] = {
        {"User-Agent", "YOUR_CUSTOM_APP_DESCRIPTION"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.squarespace.com/1.0/profiles?sortField=email&sortDirection=asc&filter=isCustomer,true;hasAccount,true",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_squarespace(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Squarespace scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create Squarespace result");
            outcome = -1;
        } else if (verify)
            outcome = verify_squarespace(ctx, keys.items[i], &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Squarespace result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"squarespace"};
static br_detector squarespace = {
    .type = 264, .version = 0, .name = "Squarespace", .custom_name = "",
    .description = "Squarespace is a website building and hosting service. Squarespace API keys can be used to manage and modify website content and configuration.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_squarespace,
};

int br_squarespace_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Squarespace detector output");
    *out = NULL;
    if (!squarespace.state &&
        br_key_pattern_init(&squarespace, "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &squarespace;
    return 0;
}
