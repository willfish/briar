/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/conversiontools/conversiontools.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { CONVERSIONTOOLS_MAX_KEY_BYTES = 167 };

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_conversiontools(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The exact ASCII capture is bounded at 167 bytes. Borrow its complete
     * Bearer value through synchronous send AND release without a heap copy. */
    char authorization[sizeof("Bearer ") + CONVERSIONTOOLS_MAX_KEY_BYTES];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    /* Preserve the source literal's 104 bytes, including spacing, no newline.
     * This POST creates a conversion task and can consume remote resources. */
    static const unsigned char payload[] =
        "{  \"type\": \"convert.website_to_jpg\",  \"options\": {    \"url\": \"http://google.com\",    \"images\": \"yes\"  }}";
    const br_http_request request = {
        .method = "POST", .url = "https://api.conversiontools.io/v1/tasks",
        .headers = headers, .nheaders = 2,
        .body = {payload, sizeof(payload) - 1}, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the WHOLE shared setup/allocation/Do error domain. ABI1 cannot
     * distinguish those stages; never classify them by diagnostic text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Source scan-defers Close ONLY; ABI1 releases
     * eagerly. Native POST redirects/full client and global parity stay open. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_conversiontools(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ConversionTools scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Preserve every occurrence;
         * finding resource failures precede the nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create ConversionTools result");
        else if (!verify || ctx) {
            if (verify) verify_conversiontools(ctx, key, &result);
            if (br_results_push(out, &result))
                rc = fail(&owned_error, "cannot append ConversionTools result");
        } /* verify && !ctx: NewRequestWithContext skips before Bearer preparation. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"conversiontools"};
static br_detector conversiontools = {
    .type = 769, .version = 0, .name = "ConversionTools", .custom_name = "",
    .description = "ConversionTools is a service used for various data conversion tasks. The API keys can be used to access and perform these tasks.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_conversiontools,
};

int br_conversiontools_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ConversionTools detector output");
    *out = NULL;
    /* Only the prefix keyword is case-insensitive. This is not JWT validation. */
    if (br_key_pattern_init(&conversiontools, "\\b(ey[a-zA-Z0-9_.]{157,165})\\b", error)) return -1;
    *out = &conversiontools;
    return 0;
}
