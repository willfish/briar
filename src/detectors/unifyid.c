/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/unifyid/unifyid.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { UNIFY_ABORT = -1, UNIFY_KEEP = 0, UNIFY_SKIP = 1 } unify_outcome;

static int unify_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static unify_outcome unify_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Constant body is built before the nil-context skip, matching NewReader
     * then NewRequestWithContext. The capture has no end boundary. */
    static const unsigned char payload[] = "{\"token\": \"sample\"}";
    char api_key[45];
    if (key.len != 44) {
        unify_fail(error, "cannot format UnifyID key");
        return UNIFY_ABORT;
    }
    memcpy(api_key, key.data, 44);
    api_key[44] = '\0';
    if (!ctx) return UNIFY_SKIP;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-API-Key", api_key},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.unify.id/v1/humandetect/verify",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    unify_outcome outcome = UNIFY_KEEP;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error) outcome = UNIFY_SKIP;
        else {
            static const unsigned char marker[] = "invalid token";
            bool invalid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = (response.status >= 200 && response.status < 300) ||
                               (response.status == 400 && invalid);
        }
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int unify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return unify_fail(error, "invalid or uninitialized UnifyID scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        unify_outcome outcome = UNIFY_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            unify_fail(&owned_error, "cannot create UnifyID result");
            outcome = UNIFY_ABORT;
        } else if (verify)
            outcome = unify_verify(ctx, key, &result, &owned_error);
        if (outcome == UNIFY_ABORT) rc = -1;
        else if (outcome == UNIFY_KEEP && br_results_push(out, &result) != 0) {
            unify_fail(&owned_error, "cannot append UnifyID result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const unify_keywords[] = {"unify"};
static br_detector unify_detector = {
    .type = 606, .version = 0, .name = "UnifyID", .custom_name = "",
    .description = "UnifyID provides human detection services. These API keys can be used to verify human presence.",
    .keywords = unify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = unify_scan,
};

int br_unifyid_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return unify_fail(error, "invalid UnifyID detector output");
    *out = NULL;
    /* No end boundary: a longer run still yields the first 44 characters. */
    if (br_key_pattern_init(&unify_detector, "\\b([0-9A-Za-z_=-]{44})", error) != 0) return -1;
    *out = &unify_detector;
    return 0;
}
