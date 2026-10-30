/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shipday/shipday.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_shipday(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shipday scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 31 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Shipday result");
        if (!rc && verify) {
            char authorization[40];
            /* Source sends the raw key after "Basic ", not a Base64 user:pass value. */
            memcpy(authorization, "Basic ", 6);
            memcpy(authorization + 6, key.data, 31);
            authorization[37] = '\0';
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {{"Authorization", authorization}};
            const br_http_request request = {
                .method = "GET", .url = "https://api.shipday.com/carriers",
                .headers = headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                response.status >= 200 && response.status < 300)
                result.verified = true;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append Shipday result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"shipday"};
static br_detector shipday = {
    .type = 625, .version = 0, .name = "Shipday", .custom_name = "",
    .description = "Shipday is a delivery management software used by businesses to manage and track their deliveries. Shipday API keys can be used to access and modify delivery data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_shipday,
};

int br_shipday_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shipday detector output");
    *out = NULL;
    if (br_key_pattern_init(&shipday, "\\b([a-zA-Z0-9.]{11}[a-zA-Z0-9]{20})\\b", error) != 0)
        return -1;
    *out = &shipday;
    return 0;
}
