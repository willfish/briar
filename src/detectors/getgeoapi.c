/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getgeoapi/getgeoapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int getgeoapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void getgeoapi_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Upstream ignores the entire Do error domain and never reads the body. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int getgeoapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getgeoapi_fail(error, "invalid or uninitialized GetGeoAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Keep every occurrence. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = getgeoapi_fail(&owned_error, "cannot create GetGeoAPI result");
        else {
            bool append = true;
            if (verify) {
                static const char prefix[] = "https://api.getgeoapi.com/v2/currency/list?api_key=";
                char url[sizeof(prefix) + 40];
                /* Literal prefix + exactly 40 lower-alphanumeric bytes + NUL:
                 * complete URL precedes the known nil-context constructor skip. */
                memcpy(url, prefix, sizeof(prefix) - 1);
                memcpy(url + sizeof(prefix) - 1, key.data, key.len);
                url[sizeof(url) - 1] = '\0';
                if (!ctx) append = false;
                else getgeoapi_verify(ctx, url, &result);
                /* Provider URL/capture/header values live through release;
                 * ordinary shared effective headers/UA end at send return. */
            }
            if (append && br_results_push(out, &result) != 0)
                rc = getgeoapi_fail(&owned_error, "cannot append GetGeoAPI result");
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

static const char *const getgeoapi_keywords[] = {"getgeoapi"};
static br_detector getgeoapi_detector = {
    .type = 383, .version = 0, .name = "GetGeoAPI", .custom_name = "",
    .description = "GetGeoAPI provides geolocation and currency conversion services. The API keys can be used to access these services and retrieve data.",
    .keywords = getgeoapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = getgeoapi_scan,
};

int br_getgeoapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getgeoapi_fail(error, "invalid GetGeoAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&getgeoapi_detector, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &getgeoapi_detector;
    return 0;
}
