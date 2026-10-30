/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paymoapp/paymoapp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    PAYMOAPP_ABORT = -1,
    PAYMOAPP_KEEP = 0,
    PAYMOAPP_DROP = 1
} paymoapp_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* DROP is only the nil-context constructor skip. It is not an attempt. */
static paymoapp_outcome verify_paymoapp(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return PAYMOAPP_DROP;
    /* Source text is already the credential. Do not Base64-encode it. */
    char authorization[51];
    _Static_assert(sizeof(authorization) == 51, "Paymoapp Authorization holds Basic plus the raw key");
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, key.data, 44);
    authorization[50] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET",
        .url = "https://app.paymoapp.com/api/me",
        .headers = headers,
        .nheaders = 2,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    /* A reached send stays unverified for every cause, including NULL.
     * Do not invent transport text or call a setter. body_error is ignored. */
    int status = response.status;
    br_http_release(ctx, &response);
    free(send_error);
    if (sent == 0 && status >= 200 && status < 300) result->verified = true;
    return PAYMOAPP_KEEP;
}

static int scan_paymoapp(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Paymoapp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keep every in-range match, including duplicates. A second copy missed by
     * one keyword is prefix consumption, not a uniqueness map. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        paymoapp_outcome outcome = PAYMOAPP_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Paymoapp finding");
            outcome = PAYMOAPP_ABORT;
        } else if (verify)
            outcome = verify_paymoapp(ctx, key, &result);
        if (outcome == PAYMOAPP_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Paymoapp finding");
            outcome = PAYMOAPP_ABORT;
        }
        br_result_clear(&result);
        if (outcome == PAYMOAPP_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"paymoapp"};
static br_detector paymoapp = {
    .type = 699,
    .version = 0,
    .name = "Paymoapp",
    .custom_name = "",
    .description = "Paymoapp is a project management and collaboration tool. Paymoapp API keys can be used to access and modify project data and user information.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_paymoapp,
};

int br_paymoapp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Paymoapp detector output");
    *out = NULL;
    if (!paymoapp.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9]{44})\\b", &regex, error) != 0)
            return -1;
        paymoapp.state = regex;
    }
    *out = &paymoapp;
    return 0;
}
