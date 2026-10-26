/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/buddyns/buddyns.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_cause(br_result *result, const char *cause)
{
    /* Source supplies zero secret arguments. Preserve token-bearing causes
     * unredacted, never log them, and treat positive 1 as a resource failure. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_buddyns(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char auth[sizeof("Token ") + 40];
    int n = snprintf(auth, sizeof(auth), "Token %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.buddyns.com/api/v2/zone/",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 598,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = set_cause(result, cause);
    /* Source ignores body/read/drain/close errors. ABI1 eagerly releases every
     * response; native Go streaming/drain/close timing parity is unestablished. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_buddyns(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_buddyns, error);
    /* Shared extraction preserves occurrences. Roll back only this invocation
     * on any nonzero failure; caller-owned findings must survive. */
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"buddyns"};
static br_detector buddyns = {
    .type = 598, .version = 0, .name = "BuddyNS", .custom_name = "",
    .description = "BuddyNS is a DNS hosting service. BuddyNS API keys can be used to manage DNS zones and records.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_buddyns,
};

int br_buddyns_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BuddyNS detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&buddyns, "\\b([0-9a-z]{40})\\b", error)) return -1;
    *out = &buddyns;
    return 0;
}
