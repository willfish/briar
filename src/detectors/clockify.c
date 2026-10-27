/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clockify/clockify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int clockify_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void clockify_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    unsigned char dedup_key[53] = "280:";
    memcpy(dedup_key + 4, key, 49); /* Exactly 48 ASCII bytes plus NUL. */
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.clockify.me/api/v1/user",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 280,
        .dedup_key = {dedup_key, 52}, /* Exact 280:KEY bytes, excluding NUL. */
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Keep the key: the unchanged ABI1 coalescing guard rejects this BEFORE
     * every injected/native send callback. Verification remains unsupported.
     * ALL send failures, including the unified setup/allocation/Do domain,
     * are suppressed without error-text classification or an error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.body_error == NULL)
        result->verified = response.status >= 200 && response.status < 300;
    /* Future supported sends must treat ANY body-error pointer, even "", as
     * Do failure: source singleflight ReadAll precedes status inspection.
     * That success predicate is currently blocked, not transport-tested.
     * Source closes the base body and scan-defers closing each replay; close
     * errors are ignored. ABI1 requires release after every send attempt. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int clockify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return clockify_fail(error, "invalid or uninitialized Clockify scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII captures leave nil context as the known
         * constructor failure: source skips rather than appends the finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; no decoding, entropy or uniqueness filter. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = clockify_fail(error, "out of memory creating Clockify result");
        else if (verify) clockify_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = clockify_fail(error, "out of memory appending Clockify result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const clockify_keywords[] = {"clockify"};
static br_detector clockify_detector = {
    .type = 280, .version = 0, .name = "Clockify", .custom_name = "",
    .description = "Clockify is a time tracking software. Clockify API keys can be used to access and modify time tracking data.",
    .keywords = clockify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = clockify_scan,
};

int br_clockify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return clockify_fail(error, "invalid Clockify detector output");
    *out = NULL;
    if (br_key_pattern_init(&clockify_detector, "\\b([a-zA-Z0-9]{48})\\b", error) != 0) return -1;
    *out = &clockify_detector;
    return 0;
}
