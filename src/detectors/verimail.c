/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/verimail/verimail.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int verimail_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verimail_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return verimail_fail(error, "invalid or uninitialized Verimail scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = verimail_fail(&owned_error, "cannot create Verimail result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://api.verimail.io/v3/verify?key=";
            char url[sizeof(prefix) + 32];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 32);
            url[sizeof(url) - 1] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = verimail_fail(&owned_error, "cannot append Verimail result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const verimail_keywords[] = {"verimail"};
static br_detector verimail_detector = {
    .type = 143, .version = 0, .name = "Verimail", .custom_name = "",
    .description = "Verimail is an email verification service that helps ensure email addresses are valid and deliverable. Verimail keys can be used to access the Verimail API for verifying email addresses.",
    .keywords = verimail_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = verimail_scan,
};

int br_verimail_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return verimail_fail(error, "invalid Verimail detector output");
    *out = NULL;
    if (br_key_pattern_init(&verimail_detector, "\\b([A-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &verimail_detector;
    return 0;
}
