/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/screenshotlayer/screenshotlayer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

/* SaneHttpClientTimeOut(10s) uses DefaultTransport, not saneTransport. The
 * local 10s timeout does not establish dial/TLS parity or add a client.
 * A nil context drops after the URL is formatted. A body-read error still
 * appends, matching the source (continue is not used). PNG is case-sensitive. */
static int verify_screenshot(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    char url[160];
    int n = snprintf(url, sizeof(url),
                     "https://api.screenshotlayer.com/api/capture?access_key=%s&url=https://google.com",
                     (const char *)secret.data);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format ScreenshotLayer URL");
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = 537,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && !response.body_error &&
        response.status >= 200 && response.status < 300 &&
        br_slice_find(response.body, (br_slice){(const unsigned char *)"PNG", 3}, 0) != SIZE_MAX)
        result->verified = true;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_screenshotlayer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ScreenshotLayer scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create ScreenshotLayer finding");
        } else if (verify) {
            int status = verify_screenshot(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ScreenshotLayer finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"screenshotlayer"};
static br_detector screenshotlayer = {
    .type = 537, .version = 0, .name = "ScreenshotLayer", .custom_name = "",
    .description = "ScreenshotLayer is a service that provides website screenshots. Access keys can be used to capture and retrieve screenshots.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_screenshotlayer,
};

int br_screenshotlayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ScreenshotLayer detector output");
    *out = NULL;
    if (br_key_pattern_init(&screenshotlayer, "\\b([a-zA-Z0-9_]{32})\\b", error) != 0) return -1;
    *out = &screenshotlayer;
    return 0;
}
