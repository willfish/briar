/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tineswebhook/tineswebhook.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int tines_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool tines_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    /* The capture is the complete GET URL. The source also passes an empty body. */
    if (!ctx) return false;
    const unsigned char empty = 0;
    const br_http_request request = {
        .method = "GET", .url = url,
        .body = {&empty, 0},
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* NoLocalAddresses is DetectorHttpClientWithNoLocalAddresses. Do errors stay silent. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int tines_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tines_fail(error, "invalid or uninitialized TinesWebhook scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Unprefixed. The host class is unbounded, so the capture itself is the URL. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len < 8 || memcmp(key.data, "https://", 8) != 0)
            rc = tines_fail(&owned_error, "invalid TinesWebhook capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = tines_fail(&owned_error, "cannot create TinesWebhook result");
        else if (verify)
            keep = tines_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = tines_fail(&owned_error, "cannot append TinesWebhook result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tines_keywords[] = {"tines.com"};
static br_detector tines_detector = {
    .type = 913, .version = 0, .name = "TinesWebhook", .custom_name = "",
    .description = "Tines is an automation platform. Tines Webhook URLs can be used to trigger and interact with Tines workflows.",
    .keywords = tines_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tines_scan,
};

int br_tineswebhook_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tines_fail(error, "invalid TinesWebhook detector output");
    *out = NULL;
    if (!tines_detector.state &&
        br_regex_compile("(https://[\\w-]+\\.tines\\.com/webhook/[a-z0-9]{32}/[a-z0-9]{32})",
                         (br_regex **)&tines_detector.state, error) != 0)
        return -1;
    *out = &tines_detector;
    return 0;
}
