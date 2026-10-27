/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/commercejs/commercejs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_commercejs(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Captures own a trailing NUL. Borrow the complete 48-byte value through
     * synchronous send/release: no Bearer prefix or heap auth duplication. */
    const br_header headers[] = {{"X-Authorization", (const char *)key.data}};
    /* Same host as ChecIO is NOT the same extraction grammar or endpoint. */
    const br_http_request request = {
        .method = "GET", .url = "https://api.chec.io/v1/categories",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source suppresses ALL Do errors. ABI1 also combines adapter setup and
     * allocation failures here; do not classify stages by diagnostic text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY; eager ABI1
     * release/full native-client configuration and global parity stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_commercejs(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid CommerceJS scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Keep occurrences and duplicate values; finding
         * resources MUST fail before the known nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create CommerceJS result");
        else if (!verify || ctx) {
            if (verify) verify_commercejs(ctx, key, &result);
            if (br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CommerceJS result");
        } /* verify && !ctx: source NewRequestWithContext failure skips candidate. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"commercejs"};
static br_detector commercejs = {
    .type = 433, .version = 0, .name = "CommerceJS", .custom_name = "",
    .description = "CommerceJS is a headless commerce platform that provides APIs for building custom e-commerce experiences. CommerceJS API keys can be used to access and manage e-commerce functionalities.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_commercejs,
};

int br_commercejs_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CommerceJS detector output");
    *out = NULL;
    /* Exact lower-alnum/underscore grammar, no ChecIO pk_ constraint. */
    if (br_key_pattern_init(&commercejs, "\\b([a-z0-9_]{48})\\b", error)) return -1;
    *out = &commercejs;
    return 0;
}
