/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/disqus/disqus.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int disqus_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor-failure continue, not a false finding. */
static bool disqus_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://disqus.com/api/3.0/trends/listThreads.json?api_key=";
    char url[124];
    _Static_assert(sizeof(prefix) - 1 + 64 + 1 == sizeof(url), "Disqus URL must be 123 bytes plus NUL");
    /* Source concatenates this bounded alphanumeric capture before request
     * construction. Constant-size byte assembly cannot fail or truncate and
     * needs no heap copy, formatting API or artificial allocation seam. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false; /* Known nil-context constructor skip follows URL preparation. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire mixed shared setup/allocation/Do failure domain,
     * without a verification-error setter or diagnostic-stage classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* The .json path does not imply response parsing. Source scan-defers Close
     * only without reading/draining, so all body/read errors are ignored. Eager
     * buffering/release, full native/private client and regexp/Reader behavior,
     * and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int disqus_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return disqus_fail(error, "invalid or uninitialized Disqus scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key cannot express constructor skip without publishing a finding.
     * Keep that outcome private, separate from nonzero helper/resource failures. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Finding resources precede URL preparation and
         * constructor skip; retain every occurrence, including duplicates. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = disqus_fail(&owned_error, "cannot create Disqus result");
        if (rc == 0 && verify) keep = disqus_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = disqus_fail(&owned_error, "cannot append Disqus result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const disqus_keywords[] = {"disqus"};
static br_detector disqus_detector = {
    .type = 789, .version = 0, .name = "Disqus", .custom_name = "",
    .description = "Disqus is a networked community platform used for web comments and discussions. Disqus API keys can be used to access and manage comments and user data.",
    .keywords = disqus_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = disqus_scan,
};

int br_disqus_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return disqus_fail(error, "invalid Disqus detector output");
    *out = NULL;
    if (br_key_pattern_init(&disqus_detector, "\\b([a-zA-Z0-9]{64})\\b", error) != 0)
        return -1;
    *out = &disqus_detector;
    return 0;
}
