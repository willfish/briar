/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flickr/flickr.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int flickr_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False means constructor skip OR successful-Do ReadAll error (source
 * continue). Mixed shared setup/allocation/Do failures instead KEEP false. */
static bool flickr_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://www.flickr.com/services/rest/?method=flickr.tags.getHotList&api_key=";
    /* Complete URL BEFORE construction. Exact 32-byte ASCII captures need no
     * encoder, formatter, heap copy, arbitrary cap or assembly failure seam. */
    char url[sizeof(base) + 32];
    _Static_assert(sizeof(url) == 109, "Flickr URL is 108 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1); memcpy(url + sizeof(base) - 1, key.data, 32); url[108] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL; bool keep = true;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without
     * setters or diagnostic classification. Only successful Do reaches ReadAll. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error != NULL) keep = false; /* Even empty errors DROP, BEFORE every status. */
        else {
            static const unsigned char marker[] = "owner=";
            result->verified = response.status >= 200 && response.status < 300 &&
                br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Entire stack URL stays live through synchronous send AND release. Source
     * scan-defers Close; ABI1 safely releases owned responses once on every send,
     * including error/DROP. Full Reader/deferred-close/native client/regexp and
     * global source/engine/output parity remain partial. Keep shared guards intact. */
    br_http_release(ctx, &response);
    free(send_error);
    return keep;
}

static int flickr_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flickr_fail(error, "invalid or uninitialized Flickr scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i); bool keep = true;
        /* TrimSpace is a no-op. Preserve every original occurrence/duplicate,
         * without validation/filter/cache. Owned finding resources precede URL
         * prep, constructor skip, read-error DROP and suppressed send outcomes. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = flickr_fail(&owned_error, "cannot create Flickr result");
        if (rc == 0 && verify) keep = flickr_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = flickr_fail(&owned_error, "cannot append Flickr result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flickr_keywords[] = {"flickr"};
static br_detector flickr_detector = {
    .type = 455, .version = 0, .name = "Flickr", .custom_name = "",
    .description = "Flickr is an image and video hosting service. Flickr API keys can be used to access and modify user data and perform various operations within the Flickr ecosystem.",
    .keywords = flickr_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = flickr_scan,
};

int br_flickr_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flickr_fail(error, "invalid Flickr detector output");
    *out = NULL;
    if (br_key_pattern_init(&flickr_detector, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &flickr_detector;
    return 0;
}
