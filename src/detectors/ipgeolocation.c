/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipgeolocation/ipgeolocation.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    IPGEOLOCATION_ABORT = -1, IPGEOLOCATION_KEEP = 0, IPGEOLOCATION_DROP = 1
} ipgeolocation_outcome;

static int ipgeolocation_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static ipgeolocation_outcome ipgeolocation_verify(const br_scan_ctx *ctx, br_slice key,
                                                  br_result *result, char **error)
{
    static const char prefix[] = "https://api.ipgeolocation.io/ipgeo?apiKey=";
    if (key.len > SIZE_MAX - sizeof(prefix)) {
        ipgeolocation_fail(error, "IPGeolocation URL too large");
        return IPGEOLOCATION_ABORT;
    }
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) {
        ipgeolocation_fail(error, "cannot construct IPGeolocation URL");
        return IPGEOLOCATION_ABORT;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The finding and full literal query precede NewRequestWithContext's
     * nil-context error, which drops this occurrence. */
    if (!ctx) {
        free(url);
        return IPGEOLOCATION_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source ignores the entire Do error domain, including ABI1's mixed
     * shared preparation failures. Never classify diagnostics or set errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore every body/read error. Provider-original URL/captures survive
     * this one release even after failed setup; synthesized effective request,
     * header-array and User-Agent storage ends at ordinary send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return IPGEOLOCATION_KEEP;
}

static int ipgeolocation_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ipgeolocation_fail(error, "invalid or uninitialized IPGeolocation scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        ipgeolocation_outcome outcome = IPGEOLOCATION_KEEP;
        /* TrimSpace is a no-op for this lowercase alphanumeric alphabet.
         * Preserve the original non-overlapping occurrences and duplicates. */
        if (key.len != 32) {
            ipgeolocation_fail(&owned_error, "invalid IPGeolocation capture");
            outcome = IPGEOLOCATION_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            ipgeolocation_fail(&owned_error, "cannot create IPGeolocation result");
            outcome = IPGEOLOCATION_ABORT;
        } else if (verify) {
            outcome = ipgeolocation_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == IPGEOLOCATION_KEEP && br_results_push(out, &result) != 0) {
            ipgeolocation_fail(&owned_error, "cannot append IPGeolocation result");
            outcome = IPGEOLOCATION_ABORT;
        }
        br_result_clear(&result);
        if (outcome == IPGEOLOCATION_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ipgeolocation_keywords[] = {"ipgeolocation"};
static br_detector ipgeolocation_detector = {
    .type = 356, .version = 0, .name = "IPGeolocation", .custom_name = "",
    .description = "IPGeolocation provides geolocation information about IP addresses. The API key can be used to access and retrieve this data.",
    .keywords = ipgeolocation_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ipgeolocation_scan,
};

int br_ipgeolocation_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ipgeolocation_fail(error, "invalid IPGeolocation detector output");
    *out = NULL;
    if (br_key_pattern_init(&ipgeolocation_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &ipgeolocation_detector;
    return 0;
}
