/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/deepgram/deepgram.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int deepgram_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int deepgram_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The nil-context constructor skip is handled before this verifier. The
     * capture is exactly 40 ASCII bytes; borrow all 46 auth bytes plus the NUL
     * on the stack through synchronous send AND release. */
    char authorization[sizeof("Token ") + 40];
    memcpy(authorization, "Token ", sizeof("Token ") - 1);
    memcpy(authorization + sizeof("Token ") - 1, key, 41);
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.deepgram.com/v1/projects",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE shared setup/allocation/Do domain, without a setter or
     * diagnostic-stage classifier. Body/read errors never alter the status. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. ABI1 eagerly
     * buffers/releases; full native client and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int deepgram_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    /* Reuse the rollback-safe shared scanner for all kept candidates. */
    if (!verify || ctx) {
        int rc = br_scan_key(detector, ctx, verify, input, out, "key", deepgram_verify, error);
        return rc == 0 ? 0 : -1;
    }
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return deepgram_fail(error, "invalid or uninitialized Deepgram scan");
    /* The shared verifier has no skip outcome. For NewRequestWithContext(nil),
     * create/clear each finding before skipping, without auth/header preparation
     * or an artificial append. TrimSpace is a no-op; retain every occurrence. */
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = deepgram_fail(&owned_error, "cannot create Deepgram result");
        br_result_clear(&result);
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const deepgram_keywords[] = {"deepgram"};
static br_detector deepgram_detector = {
    .type = 418, .version = 0, .name = "Deepgram", .custom_name = "",
    .description = "Deepgram is an automatic speech recognition (ASR) service. Deepgram API keys can be used to access and utilize Deepgram's ASR capabilities.",
    .keywords = deepgram_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = deepgram_scan,
};

int br_deepgram_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return deepgram_fail(error, "invalid Deepgram detector output");
    *out = NULL;
    if (br_key_pattern_init(&deepgram_detector, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &deepgram_detector;
    return 0;
}
