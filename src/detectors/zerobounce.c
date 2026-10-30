/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zerobounce/zerobounce.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char found_needle[] = "found";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zerobounce_verify(const br_scan_ctx *ctx, br_result *result, br_slice key)
{
    char url[128];
    char status_error[64];
    const char *cause = NULL;
    int n = snprintf(url, sizeof(url),
                     "https://api.zerobounce.net/v2/activity?email=testemail@email.com&api_key=%.*s",
                     (int)key.len, key.data);
    if (key.len != 32 || n < 0 || (size_t)n >= sizeof(url)) return -1;
    /* The key is already in the URL argument before the nil-context constructor error. */
    if (!ctx) cause = "net/http: nil Context";
    else {
        const br_http_request request = {
            .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error; /* NULL diagnostic stays NULL. */
        } else if (response.status == 200) {
            if (response.body_error) cause = response.body_error;
            else {
                br_slice needle = {(const unsigned char *)found_needle, sizeof(found_needle) - 1};
                if (br_slice_find(response.body, needle, 0) != (size_t)-1) result->verified = true;
            }
        } else if (response.status != 401 && response.status != 404) {
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
        }
        int rc = br_result_set_verification_error(result, cause, &key, 1);
        br_http_release(ctx, &response);
        free(send_error);
        return rc == 0 ? 0 : -1;
    }
    return br_result_set_verification_error(result, cause, &key, 1) == 0 ? 0 : -1;
}

static int scan_zerobounce(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Zerobounce scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Zerobounce result");
        if (!rc && verify && zerobounce_verify(ctx, &result, key) != 0)
            rc = fail(&owned_error, "cannot verify Zerobounce key");
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append Zerobounce result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"zerobounce"};
static br_detector zerobounce = {
    .type = 144, .version = 0, .name = "Zerobounce", .custom_name = "",
    .description = "Zerobounce is an email validation and verification service. Zerobounce API keys can be used to access and utilize this service.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_zerobounce,
};

int br_zerobounce_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Zerobounce detector output");
    *out = NULL;
    if (br_key_pattern_init(&zerobounce, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &zerobounce;
    return 0;
}
