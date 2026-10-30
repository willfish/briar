/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/unplugg/unplugg.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char unplugg_url[] = "https://api.unplu.gg/forecast";
static const char unplugg_body[] =
    "{\"data\":[{\"timestamp\":1466640000,\"value\":0.27589941523037853},"
    "{\"timestamp\":1466640900,\"value\":0.4059699097648263}],"
    "\"forecast_to\":1458136800,\"callback\":\"https://yourdomain.com/samplecallback\"}";

static int unplugg_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int unplugg_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                          bool *keep, char **error)
{
    *keep = false;
    if (key.len != 64) return unplugg_fail(error, "invalid Unplugg capture");
    /* The exact JSON reader is built before the context-bound constructor. */
    const br_slice body = {(const unsigned char *)unplugg_body, sizeof(unplugg_body) - 1};
    if (body.len != 191) return unplugg_fail(error, "invalid Unplugg payload");
    if (!ctx) return 0;
    char token[65];
    memcpy(token, key.data, 64);
    token[64] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Access-Token", token}, /* Header.Add canonicalizes x-access-token. */
    };
    const br_http_request request = {
        .method = "POST", .url = unplugg_url, .headers = headers, .nheaders = 2,
        .body = body, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int unplugg_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return unplugg_fail(error, "invalid or uninitialized Unplugg scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = unplugg_fail(&owned_error, "cannot create Unplugg result");
        else if (verify && unplugg_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        else if (keep && br_results_push(out, &result) != 0)
            rc = unplugg_fail(&owned_error, "cannot append Unplugg result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const unplugg_keywords[] = {"unplu"};
static br_detector unplugg_detector = {
    .type = 539, .version = 0, .name = "Unplugg", .custom_name = "",
    .description = "Unplugg is a service for forecasting and data analysis. Unplugg API keys can be used to access and manipulate forecast data.",
    .keywords = unplugg_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = unplugg_scan,
};

int br_unplugg_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return unplugg_fail(error, "invalid Unplugg detector output");
    *out = NULL;
    if (br_key_pattern_init(&unplugg_detector, "\\b([a-z0-9]{64})\\b", error) != 0) return -1;
    *out = &unplugg_detector;
    return 0;
}
