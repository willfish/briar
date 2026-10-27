/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/currentsapi/currentsapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int currentsapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int currentsapi_verify(const br_scan_ctx *ctx, br_slice token,
                             br_result *result, char **error)
{
    /* Unlike constructor-skip detectors, this verifier returns the nil-context
     * cause to FromData, which retains the finding and applies its setter. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return currentsapi_fail(error, "cannot sanitize CurrentsAPI verification error");
        return 0;
    }
    /* Captures are already NUL-terminated: borrow the complete token directly,
     * without a redundant auth/key copy, through synchronous send AND release. */
    const br_header header = {"Authorization", (const char *)token.data};
    const br_http_request request = {
        .method = "GET", .url = "https://api.currentsapi.services/v1/latest-news",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    /* Preserve the whole shared setup/allocation/Do error domain as a finding
     * error; ABI1 cannot classify its stages by diagnostic text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = currentsapi_fail(error, "cannot format CurrentsAPI status error");
            else cause = status_error;
            break;
        }
        }
    }
    /* Redact only this token, including repeated echoes, before releasing any
     * response. Every nonzero setter result is a fatal resource failure. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = currentsapi_fail(error, "cannot sanitize CurrentsAPI verification error");
    /* Status ignores all bodies/read errors. Source verifier-defers drain/close;
     * ABI1 eagerly buffers/releases. http.NoBody identity, native streaming/full
     * client configuration and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int currentsapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return currentsapi_fail(error, "invalid or uninitialized CurrentsAPI scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    /* Source inserts exact captures into a map: byte-unique tokens, not trimmed
     * occurrences. Go map iteration order is unspecified. */
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = currentsapi_fail(&owned_error, "cannot create CurrentsAPI result");
        if (rc == 0 && verify)
            rc = currentsapi_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = currentsapi_fail(&owned_error, "cannot append CurrentsAPI result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const currentsapi_keywords[] = {"currentsapi"};
static br_detector currentsapi_detector = {
    .type = 403, .version = 0, .name = "CurrentsAPI", .custom_name = "",
    .description = "CurrentsAPI provides access to the latest news and trends. CurrentsAPI keys can be used to authenticate requests and retrieve news data.",
    .keywords = currentsapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = currentsapi_scan,
};

int br_currentsapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return currentsapi_fail(error, "invalid CurrentsAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&currentsapi_detector, "([a-zA-Z0-9_-]{48})", error) != 0)
        return -1;
    *out = &currentsapi_detector;
    return 0;
}
