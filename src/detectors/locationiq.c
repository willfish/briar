/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/locationiq/locationiq.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const char locationiq_url_prefix[] = "https://us1.locationiq.com/v1/reverse.php?key=";
static const char locationiq_url_suffix[] = "&lat=-37.870662&lon=144.9803321&format=json";

typedef struct locationiq_pending locationiq_pending;
struct locationiq_pending {
    locationiq_pending *next;
    br_http_request request;
    br_http_response response;
    char url[sizeof(locationiq_url_prefix) - 1 + 35 + sizeof(locationiq_url_suffix)];
};

static int locationiq_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void locationiq_release(const br_scan_ctx *ctx, locationiq_pending *pending)
{
    while (pending) {
        locationiq_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending);
        pending = next;
    }
}

static int locationiq_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return locationiq_fail(error, "invalid or uninitialized LocationIQ scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    locationiq_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 35) {
            rc = locationiq_fail(&owned_error, "invalid LocationIQ capture");
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            rc = locationiq_fail(&owned_error, "cannot create LocationIQ result");
        } else if (verify) {
            locationiq_pending *attempt = malloc(sizeof(*attempt));
            if (!attempt) {
                rc = locationiq_fail(&owned_error, "cannot construct LocationIQ request");
            } else {
                *attempt = (locationiq_pending){0};
                memcpy(attempt->url, locationiq_url_prefix, sizeof(locationiq_url_prefix) - 1);
                memcpy(attempt->url + sizeof(locationiq_url_prefix) - 1, key.data, key.len);
                memcpy(attempt->url + sizeof(locationiq_url_prefix) - 1 + key.len,
                       locationiq_url_suffix, sizeof(locationiq_url_suffix));
                attempt->request = (br_http_request){
                    .method = "GET", .url = attempt->url,
                    .profile = BR_HTTP_SANE, .detector_type = detector->type,
                };
                /* NewRequestWithContext drops the already-created finding on
                 * nil context, after the literal URL has been assembled. */
                if (!ctx) {
                    free(attempt);
                    br_result_clear(&result);
                    continue;
                }
                char *send_error = NULL;
                if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->next = pending;
                    pending = attempt;
                } else {
                    /* The source suppresses the whole Do error domain. Shared
                     * preparation failures follow that policy, not their text. */
                    br_http_release(ctx, &attempt->response);
                    free(attempt);
                }
                free(send_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = locationiq_fail(&owned_error, "cannot append LocationIQ result");
        br_result_clear(&result);
    }
    /* Successful responses close at scan return, LIFO after publication. Keep
     * original request/URL/key storage, not synthesized headers or UA, alive
     * through release. Body/read errors do not participate in verification. */
    locationiq_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const locationiq_keywords[] = {"locationiq"};
static br_detector locationiq_detector = {
    .type = 450, .version = 0, .name = "LocationIQ", .custom_name = "",
    .description = "LocationIQ provides location-based services such as geocoding and reverse geocoding. LocationIQ API keys can be used to access these services and retrieve location data.",
    .keywords = locationiq_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = locationiq_scan,
};

int br_locationiq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return locationiq_fail(error, "invalid LocationIQ detector output");
    *out = NULL;
    if (!locationiq_detector.state) {
        br_regex *regex = NULL;
        /* The keyword is only an engine hint; direct scans are unprefixed. */
        if (br_regex_compile("\\b(pk\\.[a-zA-Z-0-9]{32})\\b", &regex, error) != 0)
            return -1;
        locationiq_detector.state = regex;
    }
    *out = &locationiq_detector;
    return 0;
}
