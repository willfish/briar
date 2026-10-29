/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipinfodb/ipinfodb.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int ipinfodb_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int ipinfodb_verify_publish(const br_scan_ctx *ctx, br_slice key,
                                   br_result *result, br_results *out, char **error)
{
    static const char prefix[] = "https://api.ipinfodb.com/v3/ip-country/?key=";
    static const char suffix[] = "&ip=8.8.8.8&format=json";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (key.len > SIZE_MAX - fixed)
        return ipinfodb_fail(error, "IPinfoDB URL too large");
    char *url = malloc(fixed + key.len);
    if (!url) return ipinfodb_fail(error, "cannot construct IPinfoDB URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
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
    char *send_error = NULL;
    int rc = 0;
    /* The entire mixed shared setup/Do error domain keeps a false finding.
     * No diagnostic classifier or verification-error setter is used. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && !response.body_error) {
        /* ReadAll and the binary substring test precede every status check.
         * Any read-error pointer, even empty, skips body projection entirely. */
        if (!response.body.data && response.body.len)
            rc = ipinfodb_fail(error, "invalid IPinfoDB response body slice");
        else {
            static const unsigned char marker[] = "\"statusCode\": \"OK\"";
            bool valid = br_slice_find(response.body,
                (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && valid;
        }
    }
    if (rc == 0 && br_results_push(out, result) != 0)
        rc = ipinfodb_fail(error, "cannot append IPinfoDB finding");
    /* Keep provider URL/captures through one ordinary release per attempt,
     * including failed preparation. Synthesized request/header-array/UA ends
     * at send return under ABI1. Source defers Close only after successful
     * ReadAll; ordinary release does not copy its deferred timing or leaks. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc == 0 ? 0 : -1;
}

static int ipinfodb_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ipinfodb_fail(error, "invalid or uninitialized IPinfoDB scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace cannot change this lowercase-alphanumeric capture. Keep
         * original occurrences and duplicates, without hex or FP filtering. */
        if (key.len != 64)
            rc = ipinfodb_fail(&owned_error, "invalid IPinfoDB capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ipinfodb_fail(&owned_error, "cannot create IPinfoDB finding");
        if (rc == 0) {
            if (verify) rc = ipinfodb_verify_publish(ctx, key, &result, out, &owned_error);
            else if (br_results_push(out, &result) != 0)
                rc = ipinfodb_fail(&owned_error, "cannot append IPinfoDB finding");
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

static const char *const ipinfodb_keywords[] = {"ipinfodb"};
static br_detector ipinfodb_detector = {
    .type = 530, .version = 0, .name = "IPinfoDB", .custom_name = "",
    .description = "IPinfoDB provides IP address geolocation services. IPinfoDB API keys can be used to access geolocation data for IP addresses.",
    .keywords = ipinfodb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ipinfodb_scan,
};

int br_ipinfodb_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ipinfodb_fail(error, "invalid IPinfoDB detector output");
    *out = NULL;
    if (br_key_pattern_init(&ipinfodb_detector, "\\b([a-z0-9]{64})\\b", error) != 0)
        return -1;
    *out = &ipinfodb_detector;
    return 0;
}
