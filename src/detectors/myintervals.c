/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/myintervals/myintervals.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int myintervals_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET. */
static int myintervals_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              bool *keep, char **error)
{
    static const char url[] = "https://api.myintervals.com/client/";
    static const unsigned char password[] = {'X'};
    *keep = false;
    if (key.len != 11) return myintervals_fail(error, "invalid MyIntervals capture");
    if (!ctx) return 0;
    /* The helper already returns "Basic ". Do not add another prefix. The
     * value must stay alive through send and release, then be freed. */
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){password, 1}, &authorization, error) != 0)
        return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Preparation and Do stay unverified, with no setter. Source never reads
     * the body, so a body_error cannot suppress a 2xx or drop the finding.
     * Release once for every attempted send, including preparation failure. */
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int myintervals_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return myintervals_fail(error, "invalid or uninitialized MyIntervals scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 11)
            rc = myintervals_fail(&owned_error, "invalid MyIntervals capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = myintervals_fail(&owned_error, "cannot create MyIntervals finding");
        if (!rc && verify)
            rc = myintervals_verify(ctx, key, &result, &keep, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = myintervals_fail(&owned_error, "cannot append MyIntervals finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const myintervals_keywords[] = {"myintervals"};
static br_detector myintervals_detector = {
    .type = 688, .version = 0, .name = "MyIntervals", .custom_name = "",
    .description = "MyIntervals is a project management tool that helps in tracking time, managing tasks, and organizing projects. MyIntervals API keys can be used to access and modify project data and user information.",
    .keywords = myintervals_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = myintervals_scan,
};

int br_myintervals_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return myintervals_fail(error, "invalid MyIntervals detector output");
    *out = NULL;
    if (br_key_pattern_init(&myintervals_detector, "\\b([0-9a-z]{11})\\b", error) != 0)
        return -1;
    *out = &myintervals_detector;
    return 0;
}
