/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/refiner/refiner.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char refiner_body[] = "id=Your-User-Id&event=Your%20event%20name";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_refiner(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Refiner scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 36 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Refiner result");
        if (!rc && verify) {
            char authorization[48];
            memcpy(authorization, "Bearer ", 7);
            memcpy(authorization + 7, key.data, 36);
            authorization[43] = '\0';
            /* Body is complete before NewRequestWithContext. Nil context skips this occurrence. */
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {
                {"Content-Type", "application/x-www-form-urlencoded"},
                {"Authorization", authorization},
            };
            const br_http_request request = {
                .method = "POST", .url = "https://api.refiner.io/v1/identify-user",
                .headers = headers, .nheaders = 2,
                .body = {(const unsigned char *)refiner_body, sizeof(refiner_body) - 1},
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
            rc = fail(&owned_error, "cannot append Refiner result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"refiner"};
static br_detector refiner = {
    .type = 288, .version = 0, .name = "Refiner", .custom_name = "",
    .description = "Refiner is a user feedback platform. Refiner keys can be used to authenticate and identify users within the Refiner platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_refiner,
};

int br_refiner_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Refiner detector output");
    *out = NULL;
    if (br_key_pattern_init(&refiner,
            "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            error) != 0)
        return -1;
    *out = &refiner;
    return 0;
}
