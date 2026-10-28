/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/endorlabs/endorlabs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int endorlabs_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int endorlabs_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret,
                             br_result *result, char **error)
{
    static const char prefix[] = "{\"key\":\"", middle[] = "\", \"secret\":\"", suffix[] = "\"}";
    char body[sizeof(prefix) - 1 + 21 + sizeof(middle) - 1 + 21 + sizeof(suffix)];
    _Static_assert(sizeof(body) == 66, "EndorLabs JSON body must be 65 bytes plus NUL");
    /* Private captures are exactly 21 JSON-safe ASCII bytes. Preserve literal
     * field order and the ONLY comma-space, without serialization or escaping.
     * Source prepares the COMPLETE body BEFORE context-bound construction. */
    size_t at = 0;
    memcpy(body + at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(body + at, key.data, key.len); at += key.len;
    memcpy(body + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(body + at, secret.data, secret.len); at += secret.len;
    memcpy(body + at, suffix, sizeof(suffix));

    const br_slice secrets[] = {key, secret}; /* Source redacts KEY THEN SECRET. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", secrets, 2) != 0)
            return endorlabs_fail(error, "cannot set EndorLabs verification error");
        return 0; /* Constructor failure RETAINS this false finding. */
    }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.endorlabs.com/v1/auth/api-key",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* Authentication can issue credentials/sessions. Acceptance is injected
     * and offline ONLY. Retain the entire mixed shared setup/allocation/Do
     * domain as a leaf cause, without diagnostic classification or stripping. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = endorlabs_fail(error, "cannot format EndorLabs verification status");
        else cause = status_error;
    }
    /* Copy and sequentially redact BEFORE release. NULL cause is the source's
     * deliberate setter no-op; every nonzero setter result is scan-fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, secrets, 2) != 0)
        rc = endorlabs_fail(error, "cannot set EndorLabs verification error");
    /* The exact complete stack body remains borrowed through send AND release.
     * Source drains/closes after status and ignores body/read/drain errors.
     * Eager buffering/release, Reader timing, private-client selection, native
     * POST redirects (still fail-closed), map ordering, full SANE/RE2 and global
     * engine/output behavior remain parity gaps. ExtraData is always nil. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int endorlabs_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return endorlabs_fail(error, "invalid or uninitialized EndorLabs scan");
    size_t original_len = out->len;
    br_captures credentials = {0};
    char *owned_error = NULL;
    /* Identical direct role patterns need only one byte-original unique set.
     * Native first-occurrence order is a choice of upstream's map order. */
    int rc = br_captures_find(detector->state, input, &credentials, true, &owned_error);
    for (size_t k = 0; rc == 0 && k < credentials.len; ++k) {
        br_slice key = br_captures_at(&credentials, k);
        for (size_t s = 0; rc == 0 && s < credentials.len; ++s) {
            br_slice secret = br_captures_at(&credentials, s);
            if (key.len == secret.len && !memcmp(key.data, secret.data, key.len)) continue;
            br_result result = {0};
            /* Fresh parts and RawV2=KEY+SECRET precede complete body prep. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret", (br_slice){0}) != 0)
                rc = endorlabs_fail(&owned_error, "cannot create EndorLabs result");
            if (rc == 0 && verify)
                rc = endorlabs_verify(ctx, key, secret, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = endorlabs_fail(&owned_error, "cannot append EndorLabs result");
            br_result_clear(&result);
            /* No verified-pair break, local cap, entropy or other filtering. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&credentials);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const endorlabs_keywords[] = {"endr+"};
static br_detector endorlabs_detector = {
    .type = 993, .version = 0, .name = "EndorLabs", .custom_name = "",
    .description = "Endorlabs provides API keys that can be used to authenticate and interact with its services. These keys should be kept confidential to prevent unauthorized access.",
    .keywords = endorlabs_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = endorlabs_scan,
};

int br_endorlabs_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return endorlabs_fail(error, "invalid EndorLabs detector output");
    *out = NULL;
    if (!endorlabs_detector.state) {
        br_regex *pattern = NULL;
        /* Direct, case-sensitive literal prefix; NOT PrefixRegex or a decoder. */
        if (br_regex_compile("\\b(endr\\+[a-zA-Z0-9-]{16})\\b", &pattern, error) != 0) return -1;
        endorlabs_detector.state = pattern;
    }
    *out = &endorlabs_detector;
    return 0;
}
