/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geoipifi/geoipifi.go. */
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    char *error;
} geoipifi_matches;

static bool verify_geoipifi(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://geo.ipify.org/api/v2/country?apiKey=";
    static const char suffix[] = "&ipAddress=8.8.8.8";
    char url[sizeof(prefix) - 1 + 32 + sizeof(suffix)];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
    /* The complete literal and finding precede NewRequestWithContext's nil
     * context rejection. Every grammar-admitted key is otherwise URL-safe. */
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* All shared setup/Do errors retain an unverified finding, without a
     * verification-error setter. Neither the body nor body_error is read. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider-owned URL survives release, including failed sends. Ordinary
     * ABI1's synthesized effective request/UA survives only through send. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int emit(void *user, const br_span *groups, size_t count)
{
    geoipifi_matches *matches = user;
    if (count < 2 || groups[1].begin == SIZE_MAX || groups[1].end > matches->input.len ||
        groups[1].end < groups[1].begin || groups[1].end - groups[1].begin != 32)
        return fail(&matches->error, "invalid GeoIpifi capture");
    br_slice key = {matches->input.data + groups[1].begin, 32};
    /* TrimSpace is a no-op for this grammar. Keep original occurrences,
     * including duplicates, without local false-positive filtering. */
    br_result result = {0};
    int rc = br_finding_key_bytes(&result, matches->detector->type, key, "key");
    if (rc != 0) rc = fail(&matches->error, "cannot create GeoIpifi result");
    else {
        bool keep = !matches->verify || verify_geoipifi(matches->ctx, key, &result);
        if (keep && br_results_push(matches->out, &result) != 0)
            rc = fail(&matches->error, "cannot append GeoIpifi result");
    }
    br_result_clear(&result);
    return rc;
}

static int scan_geoipifi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized GeoIpifi scan");
    size_t original_len = out->len;
    geoipifi_matches matches = {detector, ctx, input, out, verify, NULL};
    char *owned_error = NULL;
    int rc = br_regex_each(detector->state, input, emit, &matches, &owned_error);
    if (matches.error) { free(owned_error); owned_error = matches.error; }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"ipifi"};
static br_detector geoipifi = {
    .type = 286, .version = 0, .name = "GeoIpifi", .custom_name = "",
    .description = "GeoIpifi is a service that provides geolocation information. GeoIpifi API keys can be used to retrieve geolocation data based on IP addresses.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_geoipifi,
};

int br_geoipifi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GeoIpifi detector output");
    *out = NULL;
    if (br_key_pattern_init(&geoipifi, "\\b([a-z0-9A-Z_]{32})\\b", error) != 0) return -1;
    *out = &geoipifi;
    return 0;
}
