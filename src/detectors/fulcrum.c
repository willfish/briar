/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fulcrum/fulcrum.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fulcrum_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool fulcrum_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* Constructor failure SKIPS this occurrence. */
    /* Header preparation follows construction. Go canonicalizes X-ApiToken to
     * X-Apitoken. Borrow the complete NUL-terminated capture, without copying. */
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"X-Apitoken", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.fulcrumapp.com/api/v2/forms.json",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain. There is no
     * verification-error setter, diagnostic classifier or memory bypass. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Capture storage stays live through BOTH synchronous send and release.
     * Source scan-defers Close after successful Do and ignores body/read/close
     * errors. Eager buffering/release, Reader/close timing, private clients,
     * full native SANE/RE2 and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int fulcrum_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fulcrum_fail(error, "invalid or uninitialized Fulcrum scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences and duplicates. TrimSpace is a no-op for
     * this grammar. Finding resources precede constructor handling and skips. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fulcrum_fail(&owned_error, "cannot create Fulcrum result");
        if (rc == 0 && verify) keep = fulcrum_verify(ctx, br_captures_at(&keys, i), &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = fulcrum_fail(&owned_error, "cannot append Fulcrum result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fulcrum_keywords[] = {"fulcrum"};
static br_detector fulcrum_detector = {
    .type = 285, .version = 0, .name = "Fulcrum", .custom_name = "",
    .description = "Fulcrum is a data collection platform used to gather and analyze geospatial data. Fulcrum API tokens can be used to access and manage this data.",
    .keywords = fulcrum_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fulcrum_scan,
};

int br_fulcrum_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fulcrum_fail(error, "invalid Fulcrum detector output");
    *out = NULL;
    if (br_key_pattern_init(&fulcrum_detector, "\\b([a-z0-9]{80})\\b", error) != 0)
        return -1;
    *out = &fulcrum_detector;
    return 0;
}
