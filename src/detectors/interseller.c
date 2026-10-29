/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/interseller/interseller.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int interseller_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source request constructor's nil-context drop. */
static bool interseller_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"X-Api-Key", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://interseller.io/api/campaigns/list",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/Do error domain, without classifying
     * diagnostics. The source never reads the body or sets verification errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider captures/header values survive release. Ordinary ABI1's
     * synthesized effective headers and UA survive only through send return. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int interseller_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return interseller_fail(error, "invalid or uninitialized Interseller scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op on this lower-hex grammar. Preserve occurrences
         * and duplicates; UUID version/variant semantics are not validated. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = interseller_fail(&owned_error, "cannot create Interseller finding");
        if (rc == 0 && verify) keep = interseller_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = interseller_fail(&owned_error, "cannot append Interseller finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const interseller_keywords[] = {"interseller"};
static br_detector interseller_detector = {
    .type = 858, .version = 0, .name = "Interseller", .custom_name = "",
    .description = "Interseller is a platform for automating email outreach. Interseller API keys can be used to manage and send email campaigns.",
    .keywords = interseller_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = interseller_scan,
};

int br_interseller_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return interseller_fail(error, "invalid Interseller detector output");
    *out = NULL;
    if (!interseller_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(interseller_keywords, 1,
                "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                &regex, error) != 0)
            return -1;
        interseller_detector.state = regex;
    }
    *out = &interseller_detector;
    return 0;
}
