/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ditto/ditto.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ditto_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int ditto_verify(const br_scan_ctx *ctx, br_slice key,
                        br_result *result, char **error)
{
    /* The scanner already handled the known nil-context constructor skip.
     * Source prepares authorization AFTER construction. Keep the complete
     * bounded value borrowed through synchronous send AND release. */
    char authorization[84];
    _Static_assert(sizeof("token ") + 77 == sizeof(authorization),
                   "Ditto authorization must be 83 bytes plus NUL");
    int n = snprintf(authorization, sizeof(authorization), "token %.*s",
                     (int)key.len, (const char *)key.data);
    if (n != (int)sizeof(authorization) - 1)
        return ditto_fail(error, "cannot format Ditto authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.dittowords.com/variants",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * verification-error setter or diagnostic-text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Every body/read
     * error is ignored. Eager buffering/release, full SANE/RE2 behavior and
     * global engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int ditto_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ditto_fail(error, "invalid or uninitialized Ditto scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Keep original occurrences, including duplicates.
         * Finding resources precede constructor skipping and auth preparation;
         * br_scan_key's verifier cannot express that candidate-only SKIP. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ditto_fail(&owned_error, "cannot create Ditto result");
        else if (!verify || ctx) {
            if (verify) rc = ditto_verify(ctx, key, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = ditto_fail(&owned_error, "cannot append Ditto result");
        } /* verify && !ctx: NewRequestWithContext skips only this candidate. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ditto_keywords[] = {"ditto"};
static br_detector ditto_detector = {
    .type = 666, .version = 0, .name = "Ditto", .custom_name = "",
    .description = "Ditto is a service that provides API access to various word variants. Ditto API keys can be used to access this service and retrieve word variants.",
    .keywords = ditto_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ditto_scan,
};

int br_ditto_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ditto_fail(error, "invalid Ditto detector output");
    *out = NULL;
    /* Shape only: all lowercase alphanumeric values are allowed, not just hex.
     * This is neither UUID semantic validation nor JWT parsing. */
    if (br_key_pattern_init(&ditto_detector,
            "\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12}\\.[a-z0-9]{40})\\b",
            error) != 0) return -1;
    *out = &ditto_detector;
    return 0;
}
