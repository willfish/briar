/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipstack/ipstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { IPSTACK_ABORT = -1, IPSTACK_KEEP = 0, IPSTACK_DROP = 1 } ipstack_outcome;

static int ipstack_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool ipstack_body_verified(br_slice body)
{
    static const unsigned char continent[] = "continent_code";
    static const unsigned char restricted[] =
        "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
    /* Byte substring, not JSON, status, or a UTF-8 check. Either needle is enough. */
    return br_slice_find(body, (br_slice){continent, sizeof(continent) - 1}, 0) != SIZE_MAX
        || br_slice_find(body, (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
}

static ipstack_outcome ipstack_verify(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    static const char prefix[] = "https://api.ipstack.com/134.201.250.155?access_key=";
    if (key.len > SIZE_MAX - sizeof(prefix)) {
        ipstack_fail(error, "IpStack URL too large");
        return IPSTACK_ABORT;
    }
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) {
        ipstack_fail(error, "cannot construct IpStack URL");
        return IPSTACK_ABORT;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The finding and literal query exist before NewRequestWithContext can
     * reject a nil context. That error drops the occurrence and is not a send. */
    if (!ctx) {
        free(url);
        return IPSTACK_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    ipstack_outcome outcome = IPSTACK_KEEP;
    /* Do and shared preparation failures stay unverified. A completed read
     * error drops even when the partial body already contains a needle.
     * Neither path classifies diagnostics or calls the verification setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error) outcome = IPSTACK_DROP;
        else if (ipstack_body_verified(response.body)) result->verified = true;
    }
    /* Provider URL and captures survive this one release, including failed
     * setup. Synthesized request, header-array and User-Agent storage ends at
     * send return. Do not defer Close until the scan returns. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return outcome;
}

static int ipstack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ipstack_fail(error, "invalid or uninitialized IpStack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        ipstack_outcome outcome = IPSTACK_KEEP;
        /* TrimSpace cannot change this hex capture. Keep original ordered
         * occurrences, including duplicates. Do not use br_scan_key: it cannot
         * drop a nil-context or read-failure candidate. */
        if (key.len != 32) {
            ipstack_fail(&owned_error, "invalid IpStack capture");
            outcome = IPSTACK_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            ipstack_fail(&owned_error, "cannot create IpStack result");
            outcome = IPSTACK_ABORT;
        } else if (verify) {
            outcome = ipstack_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == IPSTACK_KEEP && br_results_push(out, &result) != 0) {
            ipstack_fail(&owned_error, "cannot append IpStack result");
            outcome = IPSTACK_ABORT;
        }
        br_result_clear(&result);
        if (outcome == IPSTACK_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ipstack_keywords[] = {"ipstack"};
static br_detector ipstack_detector = {
    .type = 133, .version = 0, .name = "IpStack", .custom_name = "",
    .description = "IpStack provides a REST API for IP geolocation services. IpStack API keys can be used to access geolocation data for IP addresses.",
    .keywords = ipstack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ipstack_scan,
};

int br_ipstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ipstack_fail(error, "invalid IpStack detector output");
    *out = NULL;
    if (br_key_pattern_init(&ipstack_detector, "\\b([a-fA-F0-9]{32})\\b", error) != 0)
        return -1;
    *out = &ipstack_detector;
    return 0;
}
