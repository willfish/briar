/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/diggernaut/diggernaut.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int diggernaut_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int diggernaut_verify(const br_scan_ctx *ctx, br_slice key,
                             br_result *result, char **error)
{
    /* The scanner already handled the known nil-context constructor skip.
     * Source prepares auth/headers AFTER construction. Borrow this complete
     * bounded value through synchronous send AND release, without heap copies. */
    char authorization[47];
    _Static_assert(sizeof("Token ") + 40 == sizeof(authorization),
                   "Diggernaut authorization must be 46 bytes plus NUL");
    int n = snprintf(authorization, sizeof(authorization), "Token %.*s",
                     (int)key.len, (const char *)key.data);
    if (n != (int)sizeof(authorization) - 1)
        return diggernaut_fail(error, "cannot format Diggernaut authorization");
    const br_header headers[] = {
        {"Accept", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://www.diggernaut.com/api/projects",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain,
     * without a verification-error setter or diagnostic-text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Status ignores
     * every body/read error. Eager buffering/release, full SANE/RE2 behavior
     * and global engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int diggernaut_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return diggernaut_fail(error, "invalid or uninitialized Diggernaut scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Preserve original occurrences and duplicates.
         * Finding failures precede the known constructor skip and auth prep;
         * br_scan_key's verifier cannot express that candidate-only SKIP. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = diggernaut_fail(&owned_error, "cannot create Diggernaut result");
        else if (!verify || ctx) {
            if (verify) rc = diggernaut_verify(ctx, key, &result, &owned_error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = diggernaut_fail(&owned_error, "cannot append Diggernaut result");
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

static const char *const diggernaut_keywords[] = {"diggernaut"};
static br_detector diggernaut_detector = {
    .type = 819, .version = 0, .name = "Diggernaut", .custom_name = "",
    .description = "Diggernaut is a web scraping service. Diggernaut API keys can be used to access and manage scraping projects and data.",
    .keywords = diggernaut_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = diggernaut_scan,
};

int br_diggernaut_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return diggernaut_fail(error, "invalid Diggernaut detector output");
    *out = NULL;
    if (br_key_pattern_init(&diggernaut_detector, "\\b([0-9a-z]{40})\\b", error) != 0)
        return -1;
    *out = &diggernaut_detector;
    return 0;
}
