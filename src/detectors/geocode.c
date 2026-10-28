/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geocode/geocode.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int geocode_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False means constructor skip, not verification rejection. */
static bool geocode_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://geocode.xyz/51.4647,0.0079?json=1&auth=";
    char url[sizeof(base) + 28];
    /* The complete bounded literal URL precedes the context-bound constructor.
     * The capture is exactly 28 original lowercase ASCII alphanumeric bytes. */
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 28);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false;

    unsigned char dedup_key[32];
    memcpy(dedup_key, "486:", 4);
    memcpy(dedup_key + 4, key.data, 28);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* DoWithDedup is mandatory. Keep the complete type:credential key and the
     * unchanged shared unsupported-coalescing guard. Suppress the whole mixed
     * setup/allocation/Do error domain, without text classification or setters. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && response.body_error == NULL) {
        static const unsigned char marker[] = "\"remaining_credits\" :";
        result->verified = response.status >= 200 && response.status < 300 &&
            br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
    }
    /* Body/status success is currently unreachable behind the shared guard.
     * Both singleflight buffering errors and subsequent read errors keep a
     * false finding. Match the literal bytes, not JSON. Stack URL/key survive
     * every send through release, including failure. Source scan-defers Close;
     * replay/close timing and full coalescing remain shared-runtime gaps. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int geocode_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return geocode_fail(error, "invalid or uninitialized Geocode scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Finding resources precede URL/construction;
         * retain original occurrences, without local filtering or cache. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = geocode_fail(&owned_error, "cannot create Geocode result");
        if (rc == 0 && verify) keep = geocode_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = geocode_fail(&owned_error, "cannot append Geocode result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const geocode_keywords[] = {"geocode"};
static br_detector geocode_detector = {
    .type = 486, .version = 0, .name = "Geocode", .custom_name = "",
    .description = "Geocode API keys can be used to access geolocation services, converting addresses into geographic coordinates and vice versa.",
    .keywords = geocode_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = geocode_scan,
};

int br_geocode_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return geocode_fail(error, "invalid Geocode detector output");
    *out = NULL;
    if (!geocode_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(geocode_keywords, 1, "\\b([a-z0-9]{28})\\b", &regex, error) != 0)
            return -1;
        geocode_detector.state = regex;
    }
    *out = &geocode_detector;
    return 0;
}
