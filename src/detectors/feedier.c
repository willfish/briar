/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/feedier/feedier.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int feedier_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool feedier_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* Constructor failure SKIPS this occurrence. */
    /* Source prepares Accept AFTER construction, BEFORE Authorization. */
    br_header headers[] = {{"Accept", "application/json"}, {"Authorization", NULL}};
    static const char prefix[] = "Bearer ";
    char authorization[sizeof(prefix) + 32];
    _Static_assert(sizeof(authorization) == 40, "Bearer value must be 39 bytes plus NUL");
    /* Private captures are exactly 32 alnum bytes. No formatter, escaping,
     * heap copy or scanner-local cap is needed for the complete Bearer value. */
    memcpy(authorization, prefix, sizeof(prefix) - 1);
    memcpy(authorization + sizeof(prefix) - 1, key.data, key.len);
    authorization[sizeof(prefix) - 1 + key.len] = '\0';
    headers[1].value = authorization;
    const br_http_request request = {
        .method = "GET", .url = "https://api.feedier.com/v1/carriers",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain, without
     * a verification-error setter, classifier or memory-diagnostic bypass. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack Authorization stays live through BOTH send and release.
     * Source scan-defers Close after successful Do and ignores body/read/close
     * errors. Eager buffering/release, Reader/close timing, private clients,
     * full native SANE/RE2 and global engine/output remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int feedier_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return feedier_fail(error, "invalid or uninitialized Feedier scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences and duplicates; TrimSpace is a no-op for
     * this capture grammar. Finding resources precede constructor handling. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = feedier_fail(&owned_error, "cannot create Feedier result");
        if (rc == 0 && verify) keep = feedier_verify(ctx, br_captures_at(&keys, i), &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = feedier_fail(&owned_error, "cannot append Feedier result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const feedier_keywords[] = {"feedier"};
static br_detector feedier_detector = {
    .type = 238, .version = 0, .name = "Feedier", .custom_name = "",
    .description = "Feedier is a feedback management platform that allows businesses to collect and analyze customer feedback. Feedier API keys can be used to access and manage feedback data.",
    .keywords = feedier_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = feedier_scan,
};

int br_feedier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return feedier_fail(error, "invalid Feedier detector output");
    *out = NULL;
    if (br_key_pattern_init(&feedier_detector, "\\b([a-z0-9A-Z]{32})\\b", error) != 0)
        return -1;
    *out = &feedier_detector;
    return 0;
}
