/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipapi/ipapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int ipapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int ipapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                        bool *keep, char **error)
{
    static const char prefix[] = "https://api.ipapi.com/49.146.239.251?access_key=";
    if (key.len > SIZE_MAX - sizeof(prefix))
        return ipapi_fail(error, "Ipapi URL too large");
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return ipapi_fail(error, "cannot construct Ipapi URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The finding and complete literal URL precede the source constructor's
     * nil-context error, which drops just this occurrence. */
    if (!ctx) {
        free(url);
        *keep = false;
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* The entire mixed shared setup/Do domain retains a false finding without
     * a setter. Diagnostic text must not determine resource provenance. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && !response.body_error) {
        /* ReadAll and binary marker evaluation precede status at every status.
         * Any read-error pointer, even empty, skips projection and keeps false. */
        if (!response.body.data && response.body.len)
            rc = ipapi_fail(error, "invalid Ipapi response body slice");
        else {
            static const unsigned char continent[] = "continent_code";
            static const unsigned char restricted[] =
                "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
            bool valid = br_slice_find(response.body,
                (br_slice){continent, sizeof(continent) - 1}, 0) != SIZE_MAX ||
                br_slice_find(response.body,
                    (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && valid;
        }
    }
    /* Provider URL/captures/finding survive one ordinary release per attempt,
     * including shared preparation failure. Synthesized request/header-array/UA
     * storage ends at send return. Source leaks and deferred closes are not copied. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc;
}

static int ipapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ipapi_fail(error, "invalid or uninitialized Ipapi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace cannot change the ASCII capture. Preserve original
         * occurrences/duplicates without a hex, entropy or local FP filter. */
        if (key.len != 32)
            rc = ipapi_fail(&owned_error, "invalid Ipapi capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ipapi_fail(&owned_error, "cannot create Ipapi finding");
        if (rc == 0 && verify)
            rc = ipapi_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ipapi_fail(&owned_error, "cannot append Ipapi finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ipapi_keywords[] = {"ipapi"};
static br_detector ipapi_detector = {
    .type = 362, .version = 0, .name = "Ipapi", .custom_name = "",
    .description = "Ipapi provides an API for IP address lookup and geolocation. Ipapi keys can be used to access this service and retrieve geolocation data for IP addresses.",
    .keywords = ipapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ipapi_scan,
};

int br_ipapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ipapi_fail(error, "invalid Ipapi detector output");
    *out = NULL;
    if (!ipapi_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(ipapi_keywords, 1, "\\b([a-z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        ipapi_detector.state = regex;
    }
    *out = &ipapi_detector;
    return 0;
}
