/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/autopilot/autopilot.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int verify_autopilot(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"autopilotapikey", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api2.autopilothq.com/v1/account",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 511,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* No error setter: upstream suppresses all verification errors. Release now
     * under ABI1 ownership rules rather than deferring Close until scan return. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_autopilot(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    /* Captures contain no whitespace, so TrimSpace is a no-op. A NULL C context
     * yields an unverified finding; upstream's nil-context request error skips it. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_autopilot, error);
}

static const char *const keywords[] = {"autopilot"};
static br_detector autopilot = {
    .type = 511, .version = 0, .name = "AutoPilot", .custom_name = "",
    .description = "AutoPilot is a marketing automation platform. AutoPilot API keys can be used "
                   "to access and manage marketing data and campaigns.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_autopilot,
};

int br_autopilot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AutoPilot detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&autopilot, "\\b([0-9a-f]{32})\\b", error) != 0) return -1;
    *out = &autopilot;
    return 0;
}
