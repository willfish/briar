/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/everhour/everhour.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int everhour_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void everhour_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Constructor's known nil-context skip precedes header preparation. Borrow
     * the complete original 32-byte capture and NUL through send AND release. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Api-Key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.everhour.com/clients",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain without a
     * setter or diagnostic classifier, retaining a false finding. A successful
     * send verifies every 2xx; body contents and read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only. Eager Reader/release timing, native/private
     * client, regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int everhour_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return everhour_fail(error, "invalid or uninitialized Everhour scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences and duplicates;
         * owned finding resources precede the known constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = everhour_fail(&owned_error, "cannot create Everhour result");
        else if (!verify || ctx) {
            if (verify) everhour_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = everhour_fail(&owned_error, "cannot append Everhour result");
        } /* Constructor skip without an artificial append/clear. */
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const everhour_keywords[] = {"everhour"};
static br_detector everhour_detector = {
    .type = 284, .version = 0, .name = "Everhour", .custom_name = "",
    .description = "Everhour is a time tracking software for teams. Everhour API keys can be used to access and manage project and time tracking data.",
    .keywords = everhour_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = everhour_scan,
};

int br_everhour_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return everhour_fail(error, "invalid Everhour detector output");
    *out = NULL;
    /* Source's unusual first class allows upper A ONLY, not B-F or a UUID;
     * later groups allow lower a-f/digits only. Never globally case-fold. */
    if (br_key_pattern_init(&everhour_detector,
            "\\b([0-9Aa-f]{4}-[0-9a-f]{4}-[0-9a-f]{6}-[0-9a-f]{6}-[0-9a-f]{8})\\b", error) != 0) return -1;
    *out = &everhour_detector;
    return 0;
}
