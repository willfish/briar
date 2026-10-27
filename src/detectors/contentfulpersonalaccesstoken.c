/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/contentfulpersonalaccesstoken/contentfulpersonalaccesstoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_contentful(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The exact 49-byte capture fits completely, with Bearer and NUL. Borrow
     * this bounded header through synchronous send AND release, without copies. */
    char authorization[7 + 49 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.contentful.com/organizations",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines setup/allocation with Do errors. Suppress the whole domain,
     * as for source Do failures, without text classification or an error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, never reading/draining the body. Body-read
     * errors are ignored; eager buffering/per-request release, full SANE client
     * behavior and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_contentful(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ContentfulPersonalAccessToken scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error) != 0 ? -1 : 0;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve every occurrence, including duplicates.
         * All finding resources precede the known nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create ContentfulPersonalAccessToken result");
        if (rc == 0) {
            result.redacted = malloc(8);
            if (!result.redacted)
                rc = fail(&owned_error, "cannot redact ContentfulPersonalAccessToken result");
            else {
                memcpy(result.redacted, "...", 3);
                memcpy(result.redacted + 3, key.data + key.len - 4, 4);
                result.redacted[7] = '\0';
            }
        }
        if (rc == 0 && (!verify || ctx)) {
            if (verify) verify_contentful(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append ContentfulPersonalAccessToken result");
        } /* verify && !ctx: source NewRequestWithContext skips the candidate. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc;
}

static const char *const keywords[] = {"CFPAT-"};
static br_detector contentful = {
    .type = 103, .version = 0, .name = "ContentfulPersonalAccessToken", .custom_name = "",
    .description = "Contentful is a content management system (CMS) that allows users to manage and deliver digital content. Contentful Personal Access Tokens can be used to access and modify this content.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_contentful,
};

int br_contentfulpersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ContentfulPersonalAccessToken detector output");
    *out = NULL;
    if (!contentful.state) {
        br_regex *pattern = NULL;
        /* Direct, case-sensitive grammar, NOT PrefixRegex. ASCII word boundaries
         * intentionally retain the trailing-hyphen/nonword boundary quirks. */
        if (br_regex_compile("\\b(CFPAT-[a-zA-Z0-9_\\-]{43})\\b", &pattern, error) != 0) return -1;
        contentful.state = pattern;
    }
    *out = &contentful;
    return 0;
}
