/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/photoroom/photoroom.go. */
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

static void rollback(br_results *out, size_t before)
{
    if (!out) return;
    while (out->len > before) br_result_clear(&out->items[--out->len]);
}

/* The production client is nil. Header.Set canonicalizes x-api-key before Do.
 * Briar keeps the supplied name. Release covers the ignored drain and close,
 * and it precedes Verified and SetVerificationError. Do not hold the response. */
static int verify_photoroom(const br_scan_ctx *ctx, const char *key, br_slice secret,
                            br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot set Photoroom verification error");
        return 0;
    }
    const br_header headers[] = {{"X-Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://image-api.photoroom.com/v1/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 1038,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false, set_error = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* A missing Do cause stays NULL. Do not invent a diagnostic. */
        cause = send_error;
        set_error = true;
    } else if (response.status == 200) {
        verified = true;
        set_error = true;
    } else if (response.status == 403) {
        set_error = true;
    } else {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format Photoroom verification status");
        else {
            cause = status_error;
            set_error = true;
        }
    }
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        if (set_error && br_result_set_verification_error(result, cause, &secret, 1) != 0)
            rc = fail(error, "cannot set Photoroom verification error");
    }
    free(send_error);
    return rc;
}

static int scan_photoroom(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Photoroom scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* First-seen order, including NoV. Go map order is unspecified and is not claimed. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
            rc = fail(&owned, "cannot create Photoroom finding");
        if (!rc && verify) rc = verify_photoroom(ctx, keys.items[i], secret, &result, &owned);
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Photoroom finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"photoroom"};
static br_detector photoroom = {
    .type = 1038, .version = 0, .name = "Photoroom", .custom_name = "",
    .description = "Photoroom is an AI photo editing platform that provides a suite of tools and services for creating and enhancing images. "
                   "Photoroom API keys can be used to access these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_photoroom,
};

int br_photoroom_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Photoroom detector output");
    *out = NULL;
    if (br_key_pattern_init(&photoroom,
                            "\\b(?:sandbox_)?(sk_pr_[a-zA-Z0-9]{1,64}_[a-fA-F0-9]{40})\\b",
                            error) != 0)
        return -1;
    *out = &photoroom;
    return 0;
}
