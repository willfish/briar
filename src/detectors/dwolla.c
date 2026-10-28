/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dwolla/dwolla.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dwolla_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int dwolla_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                          br_result *result, char **error)
{
    const br_slice secrets[] = {id, secret}; /* Source redacts ID THEN SECRET. */
    char *authorization = NULL;
    /* Source Base64 construction precedes NewRequestWithContext, even for nil
     * context. The shared byte helper owns ONE complete Basic value (143 bytes
     * including NUL for these captures), without rolling another encoder. */
    if (br_http_basic_auth(id, secret, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const unsigned char body[] = "grant_type=client_credentials";
    _Static_assert(sizeof(body) - 1 == 29, "Dwolla form body must be exactly 29 bytes");
    if (!ctx) {
        int rc = 0;
        if (br_result_set_verification_error(result, "net/http: nil Context", secrets, 2) != 0)
            rc = dwolla_fail(error, "cannot set Dwolla verification error");
        free(authorization);
        return rc; /* Constructor failure RETAINS this false finding. */
    }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api-sandbox.dwolla.com/token",
        .headers = headers, .nheaders = 2, .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* This OAuth exchange can issue sandbox credentials. Use only the injected
     * boundary. Retain the entire mixed shared setup/allocation/Do domain as a
     * leaf cause, not a classified verification rejection or scan failure. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = dwolla_fail(error, "cannot format Dwolla verification status");
        else cause = status_error;
    }
    /* Copy and sequentially redact BEFORE release. NULL cause is a deliberate
     * setter no-op; every nonzero result, including +1, is scan-fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, secrets, 2) != 0)
        rc = dwolla_fail(error, "cannot set Dwolla verification error");
    /* Complete Basic and literal form stay live through BOTH send and release.
     * Source drains/closes after status and ignores all body/read errors. Eager
     * buffering/release, Reader timing, private-client selection, native POST
     * redirects (still fail-closed), full SANE/RE2 and global engine/output
     * behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int dwolla_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dwolla_fail(error, "invalid or uninitialized Dwolla scan");
    size_t original_len = out->len;
    br_captures credentials = {0};
    char *owned_error = NULL;
    /* Identical role patterns/memberships need only one byte-unique collection.
     * Native first-occurrence order is a choice of upstream's unspecified map
     * order. No trimming, local span cap, entropy or other filtering is added. */
    int rc = br_captures_find(detector->state, input, &credentials, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < credentials.len; ++i) {
        br_slice id = br_captures_at(&credentials, i);
        for (size_t s = 0; rc == 0 && s < credentials.len; ++s) {
            br_slice secret = br_captures_at(&credentials, s);
            if (id.len == secret.len && !memcmp(id.data, secret.data, id.len)) continue;
            br_result result = {0};
            /* Fresh owned parts and RawV2=ID+SECRET precede verification. */
            if (br_finding_pair_bytes(&result, detector->type, id, "id", secret, "secret", (br_slice){0}) != 0)
                rc = dwolla_fail(&owned_error, "cannot create Dwolla result");
            if (rc == 0 && verify)
                rc = dwolla_verify(ctx, id, secret, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = dwolla_fail(&owned_error, "cannot append Dwolla result");
            br_result_clear(&result);
            /* No verified-pair break: every unequal directed pair is emitted. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&credentials);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dwolla_keywords[] = {"dwolla"};
static br_detector dwolla_detector = {
    .type = 180, .version = 0, .name = "Dwolla", .custom_name = "",
    .description = "Dwolla is a payment services provider that allows businesses to send, receive, and facilitate payments. Dwolla API keys can be used to access and manage these payment services.",
    .keywords = dwolla_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = dwolla_scan,
};

int br_dwolla_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dwolla_fail(error, "invalid Dwolla detector output");
    *out = NULL;
    if (br_key_pattern_init(&dwolla_detector, "\\b([a-zA-Z-0-9]{50})\\b", error) != 0)
        return -1;
    *out = &dwolla_detector;
    return 0;
}
