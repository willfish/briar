/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/codequiry/codequiry.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int codequiry_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void codequiry_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Borrow the complete captured string through synchronous send and release. */
    const br_header headers[] = {{"Apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://codequiry.com/api/v1/checks",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 783,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines adapter setup/allocation and Do failures. Suppress the whole
     * domain, without error-text classification or a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only without reading/draining. Eager buffering,
     * per-request release and full native client behavior remain partial.
     * Response bodies/read errors never change the status-only decision. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int codequiry_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return codequiry_fail(error, "invalid or uninitialized Codequiry scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Prepare the finding BEFORE the constructor skip:
         * owned resource failure must remain fatal even with nil context. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = codequiry_fail(error, "out of memory creating Codequiry result");
        else if (verify && !ctx) {
            /* Fixed URL/method and captured ASCII leave nil context as the known
             * constructor failure. Source skips it only in verification mode. */
            br_result_clear(&result);
            continue;
        } else if (verify) codequiry_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = codequiry_fail(error, "out of memory appending Codequiry result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const codequiry_keywords[] = {"codequiry"};
static br_detector codequiry_detector = {
    .type = 783, .version = 0, .name = "Codequiry", .custom_name = "",
    .description = "Codequiry is a plagiarism detection service. "
                   "Codequiry API keys can be used to access and utilize their plagiarism detection features.",
    .keywords = codequiry_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = codequiry_scan,
};

int br_codequiry_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return codequiry_fail(error, "invalid Codequiry detector output");
    *out = NULL;
    /* Preserve the source class, including its literal interior hyphen. */
    if (br_key_pattern_init(&codequiry_detector, "\\b([a-zA-Z-0-9]{64})\\b", error) != 0) return -1;
    *out = &codequiry_detector;
    return 0;
}
