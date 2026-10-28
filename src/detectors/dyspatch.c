/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dyspatch/dyspatch.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int dyspatch_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is an ordinary omission (constructor skip or ReadAll-error drop), NOT
 * an owned-resource failure. Shared send failures instead KEEP a false finding. */
static bool dyspatch_verify_keep(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return false; /* Known NewRequestWithContext(nil) constructor error. */
    /* Header preparation follows construction. Borrow all 59 auth bytes plus
     * the NUL on the stack through synchronous send AND release. */
    char authorization[sizeof("Bearer ") + 52];
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key, 53);
    const br_header headers[] = {
        {"Accept", "application/vnd.dyspatch.2020.11+json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.dyspatch.io/templates",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool keep = true;
    /* Suppress the entire mixed shared setup/allocation/Do domain without a
     * setter or diagnostic classifier. A failed send wins over body errors. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error != NULL) keep = false; /* Even an empty read-error string drops. */
        else {
            static const unsigned char limited[] = "limited_usage", data[] = "data";
            /* Literal binary substrings, NOT JSON fields or status-gated auth.
             * A match inside metadata or after NUL/invalid UTF-8 still counts. */
            result->verified = br_slice_find(response.body, (br_slice){limited, sizeof(limited) - 1}, 0) != SIZE_MAX ||
                               br_slice_find(response.body, (br_slice){data, sizeof(data) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Source scan-defers Close, including read-error drops. Release every ABI
     * response now; deferred-close/Reader timing, native client, regexp and
     * global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return keep;
}

static int dyspatch_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dyspatch_fail(error, "invalid or uninitialized Dyspatch scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences and duplicates;
         * finding resources precede every constructor skip or read-error drop. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = dyspatch_fail(&owned_error, "cannot create Dyspatch result");
        if (rc == 0 && (!verify || dyspatch_verify_keep(ctx, keys.items[i], &result))) {
            if (br_results_push(out, &result) != 0)
                rc = dyspatch_fail(&owned_error, "cannot append Dyspatch result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dyspatch_keywords[] = {"dyspatch"};
static br_detector dyspatch_detector = {
    .type = 258, .version = 0, .name = "Dyspatch", .custom_name = "",
    .description = "Dyspatch is a platform for managing and sending transactional emails. Dyspatch API keys can be used to access and manage email templates and sending operations.",
    .keywords = dyspatch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dyspatch_scan,
};

int br_dyspatch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dyspatch_fail(error, "invalid Dyspatch detector output");
    *out = NULL;
    if (br_key_pattern_init(&dyspatch_detector, "\\b([A-Z0-9]{52})\\b", error) != 0) return -1;
    *out = &dyspatch_detector;
    return 0;
}
