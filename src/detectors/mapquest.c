/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mapquest/mapquest.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char url_prefix[] = "https://www.mapquestapi.com/datamanager/v2/get-column-types?key=";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_mapquest(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Mapquest scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Capture runs even when verify is set and ctx is NULL. Any nonzero,
     * including +1, is fatal before a nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating Mapquest result");
        if (rc == 0 && verify) {
            /* The alphabet is 32 unreserved characters. Assemble the raw key
             * on the stack before the constructor. Do not percent-encode and
             * do not allocate the URL. */
            if (keys.lengths[i] != 32)
                rc = fail(&owned_error, "invalid Mapquest key");
            else {
                char url[sizeof(url_prefix) + 32];
                memcpy(url, url_prefix, sizeof(url_prefix) - 1);
                memcpy(url + sizeof(url_prefix) - 1, keys.items[i], 32);
                url[sizeof(url_prefix) + 31] = '\0';
                if (!ctx) {
                    /* "net/http: nil Context" drops only this candidate. */
                    br_result_clear(&result);
                    continue;
                }
                const br_http_request request = {
                    .method = "GET", .url = url,
                    .profile = BR_HTTP_SANE, .detector_type = 336,
                };
                br_http_response response = {0};
                char *transport_error = NULL;
                /* Any 2xx verifies. The body and its read error are not inspected.
                 * Other statuses and send failures stay unverified with no setter. */
                if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                    result.verified = response.status >= 200 && response.status < 300;
                br_http_release(ctx, &response);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending Mapquest result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"mapquest"};
static br_detector mapquest = {
    .type = 336, .version = 0, .name = "Mapquest", .custom_name = "",
    .description = "Mapquest is a web mapping service. Mapquest API keys can be used to access and manipulate mapping data and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_mapquest,
};

int br_mapquest_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Mapquest detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&mapquest, "\\b([0-9A-Za-z]{32})\\b", error) != 0)
        return -1;
    *out = &mapquest;
    return 0;
}
