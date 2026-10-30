/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ubidots/ubidots.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int ubidots_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int ubidots_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ubidots_fail(error, "invalid or uninitialized Ubidots scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 35 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ubidots_fail(&owned_error, "cannot create Ubidots result");
        if (rc == 0 && verify) {
            static const char url[] = "https://industrial.api.ubidots.com/api/v1.6/variables/";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            static const char h0[] = "application/json";
            const char *h1 = (const char *)key.data;
            const br_header headers[] = {{"Content-Type", h0}, {"X-Auth-Token", h1}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = ubidots_fail(&owned_error, "cannot append Ubidots result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ubidots_keywords[] = {"BBFF-"};
static br_regex *ubidots_pattern;
static br_detector ubidots_detector = {
    .type = 178, .version = 0, .name = "Ubidots", .custom_name = "",
    .description = "Ubidots is an IoT platform that provides tools to manage and analyze IoT devices. Ubidots tokens can be used to access and manipulate data from IoT devices.",
    .keywords = ubidots_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ubidots_scan,
};

int br_ubidots_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ubidots_fail(error, "invalid Ubidots detector output");
    *out = NULL;
    /* The keyword is a dispatch hint only; the source pattern is unprefixed. */
    if (!ubidots_pattern && br_regex_compile("\\b(BBFF-[0-9a-zA-Z]{30})\\b", &ubidots_pattern, error) != 0)
        return -1;
    ubidots_detector.state = ubidots_pattern;
    *out = &ubidots_detector;
    return 0;
}
