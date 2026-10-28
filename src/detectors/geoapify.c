/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geoapify/geoapify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int geoapify_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool geoapify_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://api.geoapify.com/v1/geocode/search?text=California&apiKey=";
    /* Exact 32-byte ASCII grammar: complete the literal URL before construction,
     * without URL encoding, heap staging or a fallible formatting operation. */
    char url[sizeof(base) + 32];
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 32);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false; /* NewRequestWithContext failure skips this occurrence. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole mixed shared setup/allocation/Do error domain, with no
     * text classifier or verification-error setter. Status only; never read. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* The full stack URL stays alive through synchronous send AND release.
     * ABI1 releases eagerly rather than reproducing scan-deferred Body.Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int geoapify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return geoapify_fail(error, "invalid or uninitialized Geoapify scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace is a grammar no-op. Keep occurrences and duplicates; owned
         * finding failures precede constructor skip and send suppression. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = geoapify_fail(&owned_error, "cannot create Geoapify result");
        if (rc == 0 && verify) keep = geoapify_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = geoapify_fail(&owned_error, "cannot append Geoapify result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const geoapify_keywords[] = {"geoapify"};
static br_detector geoapify_detector = {
    .type = 529, .version = 0, .name = "Geoapify", .custom_name = "",
    .description = "Geoapify provides APIs for geolocation services, including geocoding, routing, and places. Geoapify API keys can be used to access these services.",
    .keywords = geoapify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = geoapify_scan,
};

int br_geoapify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return geoapify_fail(error, "invalid Geoapify detector output");
    *out = NULL;
    if (br_key_pattern_init(&geoapify_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &geoapify_detector;
    return 0;
}
