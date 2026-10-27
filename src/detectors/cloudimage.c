/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudimage/cloudimage.go. */
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

static void verify_cloudimage(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Verification invalidates a cache. Test ONLY with an injected transport.
     * Preserve the raw Go literal's trailing LF and THREE tabs. */
    static const unsigned char payload[] =
        "{\"scope\":\"urls\",\"urls\":[\"/sample.li/paris.jpg?width=400\",\"/sample.li/flat.jpg?width=400\"]}\n\t\t\t";
    _Static_assert(sizeof(payload) - 1 == 94, "CloudImage raw payload must be exactly 94 bytes");
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-Client-Key", key}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.cloudimage.com/invalidate",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source mutates shared client.Timeout to 10s; per-request 10s plus core's
     * deadline clamp models the request, NOT shared mutation/concurrency/config.
     * Suppress the whole shared setup/allocation + Do error domain, without
     * classifying stages from error text or setting verification errors. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY; ABI1 eager
     * buffering/release and native POST redirect policy remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_cloudimage(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CloudImage scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase ASCII alnum/underscore class. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create CloudImage result");
        if (!rc && verify) {
            if (!ctx) { br_result_clear(&result); continue; } /* Constructor failure skips only this occurrence. */
            verify_cloudimage(ctx, keys.items[i], &result); /* Borrow the complete capture through release. */
        }
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CloudImage result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"cloudimage"};
static br_detector cloudimage = {
    .type = 721, .version = 0, .name = "CloudImage", .custom_name = "",
    .description = "CloudImage is a service that provides image optimization and delivery. CloudImage API keys can be used to access and modify image data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_cloudimage,
};

int br_cloudimage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudImage detector output");
    *out = NULL;
    if (br_key_pattern_init(&cloudimage, "\\b([a-z0-9_]{30})\\b", error)) return -1;
    *out = &cloudimage;
    return 0;
}
