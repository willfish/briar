/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/route4me/route4me.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int route4me_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int route4me_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return route4me_fail(error, "invalid or uninitialized Route4me scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = route4me_fail(&owned_error, "cannot create Route4me result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://api.route4me.com/api.v4/address_book.php?api_key=";
            char url[sizeof(prefix) + 32];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 32);
            url[sizeof(url) - 1] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = route4me_fail(&owned_error, "cannot append Route4me result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const route4me_keywords[] = {"route4me"};
static br_detector route4me_detector = {
    .type = 546, .version = 0, .name = "Route4me", .custom_name = "",
    .description = "Route4me is a video game database and discovery service. Route4me API keys can be used to access game data and related services.",
    .keywords = route4me_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = route4me_scan,
};

int br_route4me_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return route4me_fail(error, "invalid Route4me detector output");
    *out = NULL;
    if (br_key_pattern_init(&route4me_detector, "\\b([0-9A-Z]{32})\\b", error) != 0) return -1;
    *out = &route4me_detector;
    return 0;
}
