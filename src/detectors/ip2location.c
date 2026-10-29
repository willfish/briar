/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ip2location/ip2location.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ip2location_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int ip2location_status_cause(int status, char **cause, char **error)
{
    int needed = snprintf(NULL, 0, "unexpected HTTP response status %d", status);
    if (needed < 0) return ip2location_fail(error, "cannot format Ip2location status cause");
    *cause = malloc((size_t)needed + 1);
    if (!*cause) return ip2location_fail(error, "cannot allocate Ip2location status cause");
    if (snprintf(*cause, (size_t)needed + 1, "unexpected HTTP response status %d", status) != needed)
        return ip2location_fail(error, "cannot format Ip2location status cause");
    return 0;
}

static int ip2location_verify_publish(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, br_results *out, char **error)
{
    static const char prefix[] = "https://api.ip2location.io/?key=";
    if (key.len > SIZE_MAX - sizeof(prefix))
        return ip2location_fail(error, "Ip2location URL too large");
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return ip2location_fail(error, "cannot construct Ip2location URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The complete literal URL follows the finding and precedes the source
     * constructor's nil-context error, which drops this occurrence. */
    if (!ctx) {
        free(url);
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *status_error = NULL;
    const char *cause = NULL;
    bool set_error = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* The whole mixed shared setup/Do domain is retained through the
         * checked, token-only setter, including its NULL-cause no-op. */
        cause = send_error;
        set_error = true;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401) {
        rc = ip2location_status_cause(response.status, &status_error, error);
        cause = status_error;
        set_error = true;
    }
    /* The source never reads a body or consumes a body-read error. */
    if (rc == 0 && set_error &&
        br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = ip2location_fail(error, "cannot set Ip2location verification error");
    if (rc == 0 && br_results_push(out, result) != 0)
        rc = ip2location_fail(error, "cannot append Ip2location finding");
    /* Verdict/setter and publication precede deferred Close upstream. Release
     * once even on owned format/cause/setter/push failure, keeping the provider
     * URL, captures and causes alive. Synthesized effective request/header/UA
     * storage ends at send return under ABI1. Eager ordinary release does not
     * reproduce source deferred-close timing, draining or leaks. */
    br_http_release(ctx, &response);
    free(status_error);
    free(send_error);
    free(url);
    return rc == 0 ? 0 : -1;
}

static int ip2location_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ip2location_fail(error, "invalid or uninitialized Ip2location scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace cannot change the uppercase-alphanumeric capture. Keep
         * original occurrences and duplicates; this is not a hex/FP filter. */
        if (key.len != 32)
            rc = ip2location_fail(&owned_error, "invalid Ip2location capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ip2location_fail(&owned_error, "cannot create Ip2location finding");
        if (rc == 0) {
            if (verify) rc = ip2location_verify_publish(ctx, key, &result, out, &owned_error);
            else if (br_results_push(out, &result) != 0)
                rc = ip2location_fail(&owned_error, "cannot append Ip2location finding");
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

static const char *const ip2location_keywords[] = {"ip2location"};
static br_detector ip2location_detector = {
    .type = 940, .version = 0, .name = "Ip2location", .custom_name = "",
    .description = "Ip2location is a service that provides IP geolocation data. Ip2location keys can be used to access this geolocation data.",
    .keywords = ip2location_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ip2location_scan,
};

int br_ip2location_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ip2location_fail(error, "invalid Ip2location detector output");
    *out = NULL;
    if (!ip2location_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(ip2location_keywords, 1, "\\b([0-9A-Z]{32})\\b", &regex, error) != 0)
            return -1;
        ip2location_detector.state = regex;
    }
    *out = &ip2location_detector;
    return 0;
}
