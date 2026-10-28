/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/findl/findl.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int findl_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void findl_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Only reached after constructor handling. Borrow the complete original
     * 36-byte capture AND its terminating NUL through send AND release. */
    const br_header headers[] = {{"X-Api-Key", key}}; /* Go Header.Add canonicalizes the source spelling. */
    const br_http_request request = {
        .method = "GET", .url = "https://api.findl.com/v1.0/query?limit=6",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do failure domain,
     * retaining an ordinary false finding, without setter or text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore every body/read error. Source scan-defers Close-only; eager native
     * Reader/release timing remains partial. An explicit per-request 5s is NOT
     * source shared-client timeout mutation/persistence/race parity, including
     * mutation before constructor skips. Native/private-client/error-chain,
     * regexp and global engine/output parity remain partial; guards stay intact. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int findl_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return findl_fail(error, "invalid or uninitialized Findl scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve ALL original occurrences/duplicates.
         * Genuine owned finding failure is fatal BEFORE any constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = findl_fail(&owned_error, "cannot create Findl finding");
        else if (!verify || ctx) {
            if (verify) findl_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0) rc = findl_fail(&owned_error, "cannot append Findl finding");
        } /* Nil-context constructor error CONTINUES: never append a false result. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const findl_keywords[] = {"findl"};
static br_detector findl_detector = {
    .type = 667, .version = 0, .name = "Findl", .custom_name = "",
    .description = "Findl is a service used for searching and querying data. Findl API keys can be used to access and modify this data.",
    .keywords = findl_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = findl_scan,
};

int br_findl_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return findl_fail(error, "invalid Findl detector output");
    *out = NULL;
    /* Lower ALNUM, not hex, UUID validation or globally case-folded capture. */
    if (br_key_pattern_init(&findl_detector,
            "\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12})\\b", error) != 0) return -1;
    *out = &findl_detector;
    return 0;
}
