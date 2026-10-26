/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/calorieninja/calorieninja.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_calorieninja(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-Api-Key", key}};
    const br_http_request request = {.method = "GET", .url = "https://api.calorieninjas.com/v1/nutrition?query",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 474};
    br_http_response response = {0};
    char *error = NULL;
    /* ALL Do errors are suppressed. ABI1 also mixes adapter allocation/setup
     * failures into this nonzero domain; do not infer their stage from text. */
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close-only until scan return, without draining. ABI1
     * releases per request and may already have eagerly buffered the body. */
    br_http_release(ctx, &response);
    free(error);
}

static int scan_calorieninja(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CalorieNinja scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the reachable
         * creation failure. Source skips this candidate, not the invocation. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Captured ASCII alphanumeric bytes make source TrimSpace a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating CalorieNinja result");
        else if (verify) verify_calorieninja(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending CalorieNinja result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"calorieninja"};
static br_detector calorieninja = {
    .type = 474, .version = 0, .name = "CalorieNinja", .custom_name = "",
    .description = "CalorieNinja is a service that provides nutritional information for various foods. CalorieNinja API keys can be used to access this nutritional data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_calorieninja,
};

int br_calorieninja_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CalorieNinja detector output");
    *out = NULL;
    if (br_key_pattern_init(&calorieninja, "\\b([0-9A-Za-z]{40})\\b", error) != 0) return -1;
    *out = &calorieninja;
    return 0;
}
