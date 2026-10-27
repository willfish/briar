/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloverly/cloverly.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int cloverly_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void cloverly_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The grammar guarantees 28 bytes: complete Bearer value, no auth allocation.
     * This buffer remains live through synchronous send AND response release. */
    char authorization[36];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 28);
    authorization[35] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloverly.com/2019-03-beta/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 525,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines adapter setup/allocation and Do failures. Source suppresses
     * this whole domain; never classify by error text or call an error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only without reading/draining. Eager buffering,
     * per-request release and native client/redirect behavior remain partial.
     * Body/read errors do not affect the source status-only decision. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int cloverly_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cloverly_fail(error, "invalid or uninitialized Cloverly scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* The fixed method/URL and captured ASCII are otherwise constructor-safe.
         * Known nil-context construction failure skips verification candidates;
         * no-verification scans still retain every occurrence. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; preserve colons/underscores and duplicates. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = cloverly_fail(error, "out of memory creating Cloverly result");
        else if (verify) cloverly_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cloverly_fail(error, "out of memory appending Cloverly result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cloverly_keywords[] = {"cloverly"};
static br_detector cloverly_detector = {
    .type = 525, .version = 0, .name = "Cloverly", .custom_name = "",
    .description = "Cloverly is a platform that allows businesses to integrate carbon offsetting into their products and services. "
                   "Cloverly API keys can be used to access and manage these offsetting services.",
    .keywords = cloverly_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cloverly_scan,
};

int br_cloverly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cloverly_fail(error, "invalid Cloverly detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloverly_detector, "\\b([a-z0-9:_]{28})\\b", error) != 0) return -1;
    *out = &cloverly_detector;
    return 0;
}
