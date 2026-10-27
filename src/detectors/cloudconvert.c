/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudconvert/cloudconvert.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { CLOUDCONVERT_MAX_SECRET_SIZE = 1300 };

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_cloudconvert(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Go rejects NUL in the complete header at Client.Do. ABI1 C strings cannot
     * represent it: retain the complete finding, unverified, without any I/O. */
    if (memchr(key.data, '\0', key.len)) return;
    /* BuildRegexJWT's two dots are WILDCARD RUNES, not literal periods. The
     * maximum captured byte length is 36+4+502+4+700=1246, below source's 1300
     * size hint. This complete stack value stays borrowed through release. */
    char authorization[CLOUDCONVERT_MAX_SECRET_SIZE + sizeof("Bearer ")];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/vnd.cloudconvert+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloudconvert.com/v2/users/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the entire shared setup/allocation + Do error domain, including
     * other invalid header controls. Do not classify stages from error text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Source scan-defers Close ONLY; ABI1 may buffer
     * eagerly and release per request. Native lifecycle/config parity is open. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_cloudconvert(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CloudConvert scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* Neither the initial 'e' nor the final nonempty class is whitespace,
         * so TrimSpace is a no-op even when wildcard separators are controls. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create CloudConvert result");
        if (!rc && verify) {
            /* Known constructor failure precedes both the NUL gate and Bearer
             * preparation. No-verification still reports every occurrence. */
            if (!ctx) { br_result_clear(&result); continue; }
            verify_cloudconvert(ctx, key, &result);
        }
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CloudConvert result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"cloudconvert"};
static br_detector cloudconvert = {
    .type = 829, .version = 0, .name = "CloudConvert", .custom_name = "",
    .description = "CloudConvert is a file conversion service. CloudConvert API keys can be used to access and manage file conversion operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = CLOUDCONVERT_MAX_SECRET_SIZE, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_cloudconvert,
};

int br_cloudconvert_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudConvert detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloudconvert,
        "\\b(ey[0-9a-zA-Z]{30,34}.ey[0-9a-zA-Z-\\/_]{200,500}.[0-9a-zA-Z-\\/_]{600,700})\\b", error)) return -1;
    *out = &cloudconvert;
    return 0;
}
