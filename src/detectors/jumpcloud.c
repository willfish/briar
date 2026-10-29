/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/jumpcloud/jumpcloud.go. */
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

/* Nil context is a constructor failure and is not a send. Every attempted
 * send, including preparation failure, is released once. Do and preparation
 * errors stay unverified with no setter. Body and read errors are ignored. */
static void verify_jumpcloud(const br_scan_ctx *ctx, const char *key, br_result *result, bool *keep)
{
    if (!ctx) {
        *keep = false;
        return;
    }
    /* Header.Add canonicalizes x-api-key before Do. Briar keeps the supplied name. */
    const br_header headers[] = {{"X-Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://console.jumpcloud.com/api/v2/systemgroups",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 131,
    };
    br_http_response response = {0};
    char *error = NULL;
    if (br_http_send(ctx, &request, &response, &error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(error);
}

static int scan_jumpcloud(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Jumpcloud scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        /* Finding resources precede the constructor skip. TrimSpace is a no-op.
         * Keep source order, including duplicates from a later keyword. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Jumpcloud finding");
        if (!rc && verify) verify_jumpcloud(ctx, keys.items[i], &result, &keep);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append Jumpcloud finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"jumpcloud"};
static br_detector jumpcloud = {
    .type = 131, .version = 0, .name = "Jumpcloud", .custom_name = "",
    .description = "Jumpcloud is a cloud-based directory service platform that offers user and device management, "
                   "single sign-on, and other identity and access management (IAM) features. "
                   "Jumpcloud API keys can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_jumpcloud,
};

int br_jumpcloud_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Jumpcloud detector output");
    *out = NULL;
    if (br_key_pattern_init(&jumpcloud, "\\b([a-zA-Z0-9]{40})\\b", error) != 0) return -1;
    *out = &jumpcloud;
    return 0;
}
