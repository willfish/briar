/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clustdoc/clustdoc.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int clustdoc_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void clustdoc_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The grammar guarantees 60 bytes. Keep the complete 67-byte Bearer value
     * plus NUL on the stack and live through synchronous send AND release. */
    char authorization[68];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 60);
    authorization[67] = '\0';
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://clustdoc.com/api/users",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 513,
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

static int clustdoc_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return clustdoc_fail(error, "invalid or uninitialized ClustDoc scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and captured ASCII are otherwise constructor-safe.
         * Known nil-context construction failure skips verification candidates;
         * no-verification scans still retain every occurrence. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op. Keep every occurrence and its original case. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = clustdoc_fail(error, "out of memory creating ClustDoc result");
        else if (verify) clustdoc_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = clustdoc_fail(error, "out of memory appending ClustDoc result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const clustdoc_keywords[] = {"clustdoc"};
static br_detector clustdoc_detector = {
    .type = 513, .version = 0, .name = "ClustDoc", .custom_name = "",
    .description = "ClustDoc is a document management platform. "
                   "ClustDoc API keys can be used to access and manage documents and workflows within the ClustDoc platform.",
    .keywords = clustdoc_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = clustdoc_scan,
};

int br_clustdoc_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return clustdoc_fail(error, "invalid ClustDoc detector output");
    *out = NULL;
    if (br_key_pattern_init(&clustdoc_detector, "\\b([0-9a-zA-Z]{60})\\b", error) != 0) return -1;
    *out = &clustdoc_detector;
    return 0;
}
