/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudplan/cloudplan.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int cloudplan_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void cloudplan_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Go Header.Add canonicalizes session_id to Session_id, retaining the
     * underscore. Borrow the complete capture through send and release. */
    const br_header headers[] = {{"Session_id", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.cloudplan.biz/api/user/me",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 324,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ALL source Client.Do errors are suppressed. ABI1's unified send domain
     * also conflates adapter setup/allocation failures: those remain suppressed
     * as an explicit partial gap, without an error-text classifier or setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without draining. ABI1 eagerly buffers/
     * releases per request. Body/read/close errors never determine the result. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int cloudplan_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cloudplan_fail(error, "invalid or uninitialized Cloudplan scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the known
         * constructor failure: source skips rather than appends this finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op; this is not a UUID or hex-only grammar. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = cloudplan_fail(error, "out of memory creating Cloudplan result");
        else if (verify) cloudplan_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cloudplan_fail(error, "out of memory appending Cloudplan result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cloudplan_keywords[] = {"cloudplan"};
static br_detector cloudplan_detector = {
    .type = 324, .version = 0, .name = "Cloudplan", .custom_name = "",
    .description = "Cloudplan is a service that offers cloud-based business solutions. Cloudplan session IDs can be used to access and manage user sessions and data.",
    .keywords = cloudplan_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cloudplan_scan,
};

int br_cloudplan_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cloudplan_fail(error, "invalid Cloudplan detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloudplan_detector, "\\b([A-Z0-9-]{32})\\b", error) != 0) return -1;
    *out = &cloudplan_detector;
    return 0;
}
