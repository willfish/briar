/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cannyio/cannyio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int cannyio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void cannyio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Exactly 36 captured unreserved ASCII bytes: no escaping or heap-sized
     * payload allocation is needed, and the body excludes any terminating NUL. */
    unsigned char payload[7 + 36];
    memcpy(payload, "apiKey=", 7);
    memcpy(payload + 7, key.data, key.len);
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://canny.io/api/v1/boards/list",
        .headers = headers, .nheaders = 1, .body = {payload, sizeof(payload)},
        .profile = BR_HTTP_SANE, .detector_type = 158,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the ENTIRE nonzero adapter/Do error domain. ABI1 cannot classify
     * adapter allocation/setup separately; do not infer identity from text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers close-only until FromData returns. ABI1 instead releases
     * per request and may eagerly buffer the body; body/read errors are ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int cannyio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cannyio_fail(error, "invalid or uninitialized CannyIo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII form keys are otherwise constructor-safe.
         * Only known nil-context construction failure skips the candidate. */
        if (verify && !ctx) continue;
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace cannot change this capture's ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = cannyio_fail(error, "out of memory creating CannyIo result");
        else if (verify) cannyio_verify(ctx, key, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = cannyio_fail(error, "out of memory appending CannyIo result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const cannyio_keywords[] = {"canny"};
static br_detector cannyio_detector = {
    .type = 158, .version = 0, .name = "CannyIo", .custom_name = "",
    .description = "Canny is a user feedback tool that helps you track and prioritize feature requests. "
                   "Canny API keys can be used to access and manage feedback boards and other related data.",
    .keywords = cannyio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cannyio_scan,
};

int br_cannyio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cannyio_fail(error, "invalid CannyIo detector output");
    *out = NULL;
    if (br_key_pattern_init(&cannyio_detector,
        "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", error) != 0) return -1;
    *out = &cannyio_detector;
    return 0;
}
