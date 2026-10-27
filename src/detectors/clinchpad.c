/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clinchpad/clinchpad.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { CLINCH_ABORT = -1, CLINCH_KEEP = 0, CLINCH_SKIP = 1 } clinchpad_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static clinchpad_outcome verify_clinchpad(const br_scan_ctx *ctx, br_slice key,
                                          br_result *result, char **error)
{
    static const unsigned char username[] = "api-key";
    char *authorization = NULL;
    /* Source prepares Base64("api-key:"+KEY) BEFORE NewRequestWithContext.
     * The Basic helper's positive failure must abort, not become SKIP. */
    if (br_http_basic_auth((br_slice){username, sizeof(username) - 1}, key, &authorization, error)) {
        free(authorization);
        return CLINCH_ABORT;
    }
    if (!ctx) { free(authorization); return CLINCH_SKIP; }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.clinchpad.com/api/v1/pipelines",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the entire shared send/setup error domain. ABI1 cannot split
     * adapter allocation/setup from Client.Do; never infer stages from text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close ONLY and ignores its error. ABI1 can eagerly
     * buffer/read/release, so neither timing nor full client config is parity. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return CLINCH_KEEP;
}

static int scan_clinchpad(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Clinchpad scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; clinchpad_outcome outcome = CLINCH_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this lowercase ASCII alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Clinchpad result"); outcome = CLINCH_ABORT;
        }
        if (outcome == CLINCH_KEEP && verify) outcome = verify_clinchpad(ctx, key, &result, &owned_error);
        if (outcome == CLINCH_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Clinchpad result"); outcome = CLINCH_ABORT;
        }
        br_result_clear(&result); /* SKIP discards only this constructor-failed candidate. */
        if (outcome == CLINCH_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"clinchpad"};
static br_detector clinchpad = {
    .type = 255, .version = 0, .name = "Clinchpad", .custom_name = "",
    .description = "Clinchpad is a CRM tool. Clinchpad API keys can be used to access and modify data within Clinchpad.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_clinchpad,
};

int br_clinchpad_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Clinchpad detector output");
    *out = NULL;
    if (br_key_pattern_init(&clinchpad, "\\b([a-z0-9]{32})\\b", error)) return -1;
    *out = &clinchpad;
    return 0;
}
