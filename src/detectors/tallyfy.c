/* SPDX-License-Identifier: AGPL-3.0-only */
/* Tallyfy, from pinned TruffleHog pkg/detectors/tallyfy/tallyfy.go. Duplicates are kept. */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.tallyfy.com/me";
static const char capture[] =
    "\\b([0-9A-Za-z]{36}\\.[0-9A-Za-z]{264}\\.[0-9A-Za-z\\-_]{683})\\b";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *token, br_result *result, char **error)
{
    if (!ctx) return 1;
    size_t token_len = strlen(token);
    char *bearer = malloc(7 + token_len + 1);
    if (!bearer) return fail(error, "cannot format Tallyfy authorization");
    memcpy(bearer, "Bearer ", 7);
    memcpy(bearer + 7, token, token_len + 1);
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", bearer}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .timeout_ms = 5000, .detector_type = 719, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    free(bearer);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Tallyfy scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key(&result, detector->type, found.items[i], "key") != 0)
            rc = fail(&owned, "cannot create Tallyfy finding");
        else if (verify_requested && (outcome = verify(ctx, found.items[i], &result, &owned)) < 0)
            rc = -1;
        else if (!outcome && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Tallyfy finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Tallyfy", .type = 719, .description =
        "Tallyfy is a process management and workflow automation platform. Tallyfy API keys can be used to access and automate workflows and processes within the platform.",
    .keywords = (const char *[]){"tallyfy", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_tallyfy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Tallyfy detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, capture, error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
