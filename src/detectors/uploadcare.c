/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/uploadcare/uploadcare.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_uploadcare(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized UploadCare scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source compiles the same 20-character pattern for the private and public keys. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t p = 0; !rc && p < keys.len; ++p) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice public_key = br_captures_at(&keys, p);
            if (key.len != 20 || public_key.len != 20 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(&owned_error, "cannot create UploadCare result");
            if (!rc && verify) {
                /* NewRequestWithContext precedes both headers. Nil context skips this pair. */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                char authorization[64];
                int n = snprintf(authorization, sizeof(authorization), "Uploadcare.Simple %.*s:%.*s",
                                 20, public_key.data, 20, key.data);
                if (n < 0 || (size_t)n >= sizeof(authorization)) {
                    br_result_clear(&result);
                    rc = fail(&owned_error, "cannot build UploadCare authorization");
                    break;
                }
                const br_header headers[] = {
                    {"Accept", "application/vnd.uploadcare-v0.5+json"},
                    {"Authorization", authorization},
                };
                const br_http_request request = {
                    .method = "GET", .url = "https://api.uploadcare.com/files/",
                    .headers = headers, .nheaders = 2,
                    .profile = BR_HTTP_SANE, .detector_type = detector->type,
                };
                br_http_response response = {0};
                char *send_error = NULL;
                if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                    response.status >= 200 && response.status < 300)
                    result.verified = true;
                br_http_release(ctx, &response);
                free(send_error);
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append UploadCare result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"uploadcare"};
static br_detector uploadcare = {
    .type = 722, .version = 0, .name = "UploadCare", .custom_name = "",
    .description = "UploadCare is a service for handling file uploads and transformations. UploadCare keys can be used to manage and access files within the UploadCare system.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = scan_uploadcare,
};

int br_uploadcare_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid UploadCare detector output");
    *out = NULL;
    if (br_key_pattern_init(&uploadcare, "\\b([a-z0-9]{20})\\b", error) != 0) return -1;
    *out = &uploadcare;
    return 0;
}
