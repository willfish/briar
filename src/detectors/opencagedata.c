/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/opencagedata/opencagedata.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char opencagedata_prefix[] =
    "https://api.opencagedata.com/geocode/v1/json?q=12.8797,121.7740&key=";

static int opencagedata_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Complete literal URL, including the raw key. Checked before the nil-context
 * drop so a constructor skip is never a substitute for a failed construction. */
static int opencagedata_url(const char *key, char *url, size_t n, char **error)
{
    int wrote = snprintf(url, n, "%s%s", opencagedata_prefix, key);
    if (wrote < 0 || (size_t)wrote >= n || (size_t)wrote != sizeof(opencagedata_prefix) - 1 + 32)
        return opencagedata_fail(error, "cannot format OpenCageData URL");
    return 0;
}

/* DoWithDedup is mandatory. The nonempty key stays set so ABI1's coalescing
 * guard rejects a borrowed transport before prepare. Do not clear it or call
 * a lower send. URL and key stay alive through send and release. */
static void opencagedata_verify(const br_scan_ctx *ctx, const char *url, const char *key,
                                br_result *result)
{
    unsigned char dedup_key[36];
    memcpy(dedup_key, "533:", 4);
    memcpy(dedup_key + 4, key, 32);
    const br_http_request request = {
        .method = "GET",
        .url = url,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, 36}, /* Exact 533:KEY, no trailing NUL. */
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    /* A reached send stays unverified for every cause, including NULL and the
     * native coalescing rejection. Do not invent or publish transport text. */
    free(transport_error);
    if (send_rc == 0 && response.status >= 200 && response.status < 300)
        result->verified = true; /* body_error does not change a successful send. */
    br_http_release(ctx, &response); /* One release for this attempted send. */
}

static int opencagedata_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return opencagedata_fail(error, "invalid or uninitialized OpenCageData scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match. The upstream duplicate case is prefix
     * consumption, not a uniqueness map. Any nonzero, including +1, is fatal. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0 && !owned_error) owned_error = strdup("cannot scan OpenCageData matches");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        char url[sizeof(opencagedata_prefix) + 32];
        /* TrimSpace is a no-op for this alphabet. Finding failure, including
         * +1, is fatal before URL construction, skip, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = opencagedata_fail(&owned_error, "cannot create OpenCageData result");
        else if (verify && opencagedata_url(keys.items[i], url, sizeof(url), &owned_error) != 0)
            rc = -1;
        else if (verify && !ctx) {
            /* URL is complete. Nil context drops before prepare, send, and
             * release. A constructor skip is not an attempt. */
        } else {
            if (verify) opencagedata_verify(ctx, url, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = opencagedata_fail(&owned_error, "cannot append OpenCageData result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const opencagedata_keywords[] = {"opencagedata"};
static const char opencagedata_capture[] = "\\b([a-z0-9]{32})\\b";
static br_detector opencagedata_detector = {
    .type = 533,
    .version = 0,
    .name = "OpenCageData",
    .custom_name = "",
    .description = "OpenCageData provides a geocoding API to convert coordinates to and from places. OpenCageData keys can be used to access the service's geocoding capabilities.",
    .keywords = opencagedata_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = opencagedata_scan,
};

int br_opencagedata_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return opencagedata_fail(error, "invalid OpenCageData detector output");
    *out = NULL;
    if (!opencagedata_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(opencagedata_keywords, 1, opencagedata_capture, &regex, error) != 0)
            return -1;
        opencagedata_detector.state = regex;
    }
    *out = &opencagedata_detector;
    return 0;
}
