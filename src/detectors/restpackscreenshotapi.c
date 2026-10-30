/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/restpackscreenshotapi. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_restpack(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    (void)error;
    if (!ctx) return 1;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Access-Token", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://restpack.io/api/screenshot/usage",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_restpack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized RestpackScreenshotAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create RestpackScreenshotAPI result");
            outcome = -1;
        } else if (verify)
            outcome = verify_restpack(ctx, keys.items[i], &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append RestpackScreenshotAPI result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"restpack"};
static br_detector restpack = {
    .type = 518, .version = 0, .name = "RestpackScreenshotAPI", .custom_name = "",
    .description = "Restpack Screenshot API is a service used to capture screenshots of web pages. The API key can be used to authenticate requests to the service.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_restpack,
};

int br_restpackscreenshotapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid RestpackScreenshotAPI detector output");
    *out = NULL;
    if (!restpack.state && br_key_pattern_init(&restpack, "\\b([0-9A-Za-z]{48})\\b", error) != 0)
        return -1;
    *out = &restpack;
    return 0;
}
