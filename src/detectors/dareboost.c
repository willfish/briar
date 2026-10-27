/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dareboost/dareboost.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DAREBOOST_ABORT = -1, DAREBOOST_KEEP = 0, DAREBOOST_SKIP = 1
} dareboost_outcome;

static int dareboost_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static dareboost_outcome dareboost_verify(const br_scan_ctx *ctx, br_slice key,
                                          br_result *result, char **error)
{
    /* The 60-byte ASCII capture needs no escaping. Preserve the source's four
     * spaces after both '{' and ','; borrow the complete body through send AND
     * release, without a heap copy or JSON encoder. */
    char payload[sizeof("{    \"token\": \"") - 1 + 60 + sizeof("\",    \"location\": \"Paris\"}")];
    int n = snprintf(payload, sizeof(payload), "{    \"token\": \"%.*s\",    \"location\": \"Paris\"}",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(payload)) {
        dareboost_fail(error, "cannot format Dareboost payload");
        return DAREBOOST_ABORT;
    }
    /* Source prepares the body before NewRequestWithContext's nil-context skip. */
    if (!ctx) return DAREBOOST_SKIP;
    const br_header header = {"Content-Type", "application/json"};
    const br_http_request request = {
        .method = "POST", .url = "https://api.dareboost.com/0.8/config",
        .headers = &header, .nheaders = 1,
        .body = {(const unsigned char *)payload, (size_t)n},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    dareboost_outcome outcome = DAREBOOST_KEEP;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * here: suppress that entire domain without a setter or text classifier.
     * Failed sends retain the finding regardless of any populated body error. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error != NULL) {
            outcome = DAREBOOST_SKIP; /* ReadAll failure drops only this occurrence, at every status. */
        } else {
            static const unsigned char success[] = "\"status\":200";
            bool found = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && found;
        }
    }
    /* Source leaks on read failure and scan-defers Close after read success.
     * Always release ABI-owned responses instead. Native streaming/deferred
     * close, POST redirects/full client and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int dareboost_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dareboost_fail(error, "invalid or uninitialized Dareboost scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        dareboost_outcome outcome = DAREBOOST_KEEP;
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates;
         * finding resources fail before body preparation or any skip/drop. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            dareboost_fail(&owned_error, "cannot create Dareboost result");
            outcome = DAREBOOST_ABORT;
        }
        if (outcome == DAREBOOST_KEEP && verify)
            outcome = dareboost_verify(ctx, key, &result, &owned_error);
        if (outcome == DAREBOOST_KEEP && br_results_push(out, &result) != 0) {
            dareboost_fail(&owned_error, "cannot append Dareboost result");
            outcome = DAREBOOST_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DAREBOOST_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dareboost_keywords[] = {"dareboost"};
static br_detector dareboost_detector = {
    .type = 762, .version = 0, .name = "Dareboost", .custom_name = "",
    .description = "Dareboost is a website performance monitoring tool. Dareboost API keys can be used to access and modify performance monitoring configurations.",
    .keywords = dareboost_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dareboost_scan,
};

int br_dareboost_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dareboost_fail(error, "invalid Dareboost detector output");
    *out = NULL;
    if (br_key_pattern_init(&dareboost_detector, "\\b([0-9a-zA-Z]{60})\\b", error) != 0)
        return -1;
    *out = &dareboost_detector;
    return 0;
}
