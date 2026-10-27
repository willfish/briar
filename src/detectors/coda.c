/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coda/coda.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { CODA_ABORT = -1, CODA_KEEP = 0, CODA_SKIP = 1 } coda_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static coda_outcome verify_coda(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return CODA_SKIP; /* Source constructor failure skips this candidate. */
    char authorization[44] = "Bearer "; /* 7+36+NUL, complete bounded capture. */
    memcpy(authorization + 7, key.data, key.len); authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    /* ctx.transport supplies the existing client injection seam. It does not
     * widen this provider into another HTTP profile or full Go client model. */
    const br_http_request request = {
        .method = "GET", .url = "https://coda.io/apis/v1/whoami",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* Copy and redact CURRENT KEY only, before releasing any cause owner.
     * Setter +1 is resource ABORT, never the constructor SKIP value. */
    int rc = br_result_set_verification_error(result, cause, &key, 1);
    /* Body/read errors are ignored, including on 2xx. Source scan-defers Close
     * ONLY; eager ABI1 buffering/release, native diagnostics and full private
     * client configuration remain explicit parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc) { fail(error, "cannot store Coda verification error"); return CODA_ABORT; }
    return CODA_KEEP;
}

static int scan_coda(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Coda scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; coda_outcome outcome = CODA_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace changes nothing; retain occurrences and duplicate values. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Coda result"); outcome = CODA_ABORT;
        }
        if (outcome == CODA_KEEP && verify) outcome = verify_coda(ctx, key, &result, &owned_error);
        if (outcome == CODA_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Coda result"); outcome = CODA_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CODA_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"coda"};
static br_detector coda = {
    .type = 960, .version = 0, .name = "Coda", .custom_name = "",
    .description = "Coda is a platform for building collaborative documents and applications. Coda API keys can be used to access and manipulate data within Coda documents and applications.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_coda,
};

int br_coda_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Coda detector output");
    *out = NULL;
    /* Lowercase ALNUM UUID shape, not hex or UUID-version validation. */
    if (br_key_pattern_init(&coda, "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", error)) return -1;
    *out = &coda;
    return 0;
}
