/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dynalist/dynalist.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int dynalist_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False means the constructor skipped this occurrence, NOT a verification
 * rejection. Every shared setup/allocation/Do/read failure instead retains it. */
static bool dynalist_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Source prepares its literal body BEFORE the context-bound constructor.
     * Exact 128-byte ASCII grammar needs no escaping/serializer/heap copy. */
    char payload[142];
    memcpy(payload, "{\"token\": \"", 11);
    memcpy(payload + 11, key.data, 128);
    memcpy(payload + 139, "\"}", 3);
    if (!ctx) return false;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://dynalist.io/api/v1/file/list",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * setter, diagnostic classification or candidate loss. Successful ReadAll
     * (including checking EMPTY non-NULL read errors) precedes EVERY status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && response.body_error == NULL) {
        static const unsigned char marker[] = "\"_code\":\"Ok\"";
        bool valid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        if (response.status >= 200 && response.status < 300) result->verified = valid;
    }
    /* Stack body is live through synchronous send AND release. Source defers
     * Close only after successful ReadAll, even leaking on read error; ABI1
     * releases its owned response on every send. Full Reader/deferred-close,
     * client/regexp and global source/engine/output parity remain partial.
     * Keep native POST redirect handling fail-closed in the unchanged adapter. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int dynalist_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dynalist_fail(error, "invalid or uninitialized Dynalist scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates, with
         * no local filtering or cache. Finding resources precede body and skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = dynalist_fail(&owned_error, "cannot create Dynalist result");
        if (rc == 0 && verify) keep = dynalist_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = dynalist_fail(&owned_error, "cannot append Dynalist result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dynalist_keywords[] = {"dynalist"};
static br_detector dynalist_detector = {
    .type = 359, .version = 0, .name = "Dynalist", .custom_name = "",
    .description = "Dynalist is a web-based outlining app that allows users to create and manage hierarchical lists. Dynalist API tokens can be used to access and manipulate these lists programmatically.",
    .keywords = dynalist_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dynalist_scan,
};

int br_dynalist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dynalist_fail(error, "invalid Dynalist detector output");
    *out = NULL;
    if (br_key_pattern_init(&dynalist_detector, "\\b([a-zA-Z0-9-_]{128})\\b", error) != 0) return -1;
    *out = &dynalist_detector;
    return 0;
}
