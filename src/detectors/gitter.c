/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gitter/gitter.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int gitter_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source's constructor-error continue, not rejection. */
static bool gitter_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    /* The fixed URL and grammar leave only nil context as a constructor error.
     * Authorization is assembled after that constructor, without formatting or
     * another allocation. Both original provider values survive release. */
    char authorization[sizeof("Bearer ") + 40];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 40);
    authorization[47] = '\0';
    unsigned char dedup_key[44];
    memcpy(dedup_key, "555:", 4);
    memcpy(dedup_key + 4, key.data, 40);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.gitter.im/v1/user/me",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Keep the entire key: borrowed transports must remain guarded. The owned
     * source client buffers before Do returns, promoting read errors to Do
     * errors. All mixed setup/Do errors leave a false finding without a setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int gitter_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gitter_fail(error, "invalid or uninitialized Gitter scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op for this alphabet. Preserve original occurrences
         * and construct each finding before any nil-context skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = gitter_fail(&owned_error, "cannot create Gitter result");
        if (rc == 0 && verify) keep = gitter_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = gitter_fail(&owned_error, "cannot append Gitter result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const gitter_keywords[] = {"gitter"};
static br_detector gitter_detector = {
    .type = 555, .version = 0, .name = "Gitter", .custom_name = "",
    .description = "Gitter is a chat and networking platform. Gitter API keys can be used to access and interact with Gitter services and data.",
    .keywords = gitter_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = gitter_scan,
};

int br_gitter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gitter_fail(error, "invalid Gitter detector output");
    *out = NULL;
    if (!gitter_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(gitter_keywords, 1, "\\b([a-z0-9-]{40})\\b", &regex, error) != 0)
            return -1;
        gitter_detector.state = regex;
    }
    *out = &gitter_detector;
    return 0;
}
