/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/madkudu/madkudu.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_madkudu(const br_scan_ctx *ctx, br_slice key,
                          br_result *result, char **error)
{
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    br_http_request request = {
        .method = "GET", .url = "https://api.madkudu.com/v1/ping",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The source suppresses the whole mixed preparation/Do error domain,
     * never calls the error setter and ignores response bodies/read errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* Provider auth stays alive through release; synthesized ABI1 headers and
     * User-Agent belong to send only, not to this provider's release. */
    free(send_error);
    free(authorization);
    return 0;
}

static int scan_madkudu(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized MadKudu scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for lowercase hex. Construct the complete
         * finding before NewRequestWithContext's reachable nil-context skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            rc = fail(&owned_error, "cannot create MadKudu finding");
        } else if (verify && !ctx) {
            br_result_clear(&result);
            continue;
        } else if (verify) {
            rc = verify_madkudu(ctx, key, &result, &owned_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append MadKudu finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"madkudu"};
static br_detector madkudu = {
    .type = 715, .version = 0, .name = "MadKudu", .custom_name = "",
    .description = "MadKudu is a predictive lead scoring service that helps B2B companies identify the best-fit leads based on data. MadKudu API keys can be used to access and manipulate lead scoring data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_madkudu,
};

int br_madkudu_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid MadKudu detector output");
    *out = NULL;
    if (br_key_pattern_init(&madkudu, "\\b([0-9a-f]{32})\\b", error) != 0) return -1;
    *out = &madkudu;
    return 0;
}
