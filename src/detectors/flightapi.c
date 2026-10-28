/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flightapi/flightapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int flightapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void flightapi_verify(const br_scan_ctx *ctx, const char url[70], br_result *result)
{
    /* Constructor's known nil-context skip has passed. Borrow the complete
     * stack URL through send AND release; only common UA is added. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, keeping a
     * false finding without setter/classifier. All successful-send 2xx verify;
     * response contents and read errors are deliberately ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close; ABI1 eagerly reads/releases owned responses,
     * even failures. Reader/native/private client/regexp and global parity
     * remain partial. Verification tests must be strictly injected/offline. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int flightapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flightapi_fail(error, "invalid or uninitialized FlightApi scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences and duplicates,
         * with no hex validation, global capture folding, filter or cache. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = flightapi_fail(&owned_error, "cannot create FlightApi result");
        char url[70];
        if (rc == 0 && verify) {
            /* Finding THEN complete URL BEFORE constructor skip. KEY24 permits
             * bounded literal assembly, no encoder/formatter/heap copy or cap. */
            memcpy(url, "https://api.flightapi.io/iata/", 30);
            memcpy(url + 30, keys.items[i], 24);
            memcpy(url + 54, "/london/airport", 16); /* Includes the final NUL. */
        }
        if (rc == 0 && (!verify || ctx)) {
            if (verify) flightapi_verify(ctx, url, &result);
            if (br_results_push(out, &result) != 0)
                rc = flightapi_fail(&owned_error, "cannot append FlightApi result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flightapi_keywords[] = {"flightapi"};
static br_detector flightapi_detector = {
    .type = 528, .version = 0, .name = "FlightApi", .custom_name = "",
    .description = "FlightApi is a service used for accessing flight-related data. FlightApi keys can be used to query flight information and other related services.",
    .keywords = flightapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flightapi_scan,
};

int br_flightapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flightapi_fail(error, "invalid FlightApi detector output");
    *out = NULL;
    if (br_key_pattern_init(&flightapi_detector, "\\b([a-z0-9]{24})\\b", error) != 0) return -1;
    *out = &flightapi_detector;
    return 0;
}
