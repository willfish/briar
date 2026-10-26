/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/browshot. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    /* Source provides ZERO secret arguments, even for query-key echoes. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_browshot(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    static const char endpoint[] = "https://api.browshot.com/api/v1/instance/list?key=";
    /* The capture is exactly 28 query-safe ASCII alphanumeric/hyphen bytes. */
    char url[sizeof(endpoint) + 28];
    snprintf(url, sizeof(url), "%s%s", endpoint, key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 400: case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Status alone matters. Body/read/drain/close errors are ignored; ABI1's
     * eager response release does not establish native Go streaming timing. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_browshot(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    /* TrimSpace is a no-op for the source alphabet. Keep every occurrence. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_browshot, error);
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"browshot"};
static br_detector browshot = {
    .type = 448, .version = 0, .name = "Browshot", .custom_name = "",
    .description = "Browshot is a service that allows you to take screenshots of web pages from different browsers and devices. Browshot API keys can be used to automate and manage these screenshots.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_browshot,
};

int br_browshot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Browshot detector output");
    *out = NULL;
    /* Preserve the source's literal hyphen and word-boundary behavior. */
    if (br_key_pattern_init(&browshot, "\\b([a-zA-Z-0-9]{28})\\b", error)) return -1;
    *out = &browshot;
    return 0;
}
