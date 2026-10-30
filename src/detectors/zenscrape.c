/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zenscrape/zenscrape.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { ZEN_ABORT = -1, ZEN_KEEP = 0 } zen_outcome;

static int zen_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zen_cause(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return zen_fail(error, "cannot set Zenscrape verification error");
    return 0;
}

static zen_outcome zen_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char api_key[37];
    if (key.len != 36) {
        zen_fail(error, "cannot format Zenscrape key");
        return ZEN_ABORT;
    }
    memcpy(api_key, key.data, 36);
    api_key[36] = '\0';
    /* http.NoBody. Nil context is a verification error, not a skip. The key is
     * passed to SetVerificationError. */
    if (!ctx) {
        if (zen_cause(result, "net/http: nil Context", key, error) != 0) return ZEN_ABORT;
        return ZEN_KEEP;
    }
    const br_header headers[] = {{"apikey", api_key}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.zenscrape.com/api/v1/status",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200 || response.status == 429)
        result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            zen_fail(error, "cannot format Zenscrape status");
            return ZEN_ABORT;
        }
        cause = status_error;
    }
    int rc = zen_cause(result, cause, key, error);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? ZEN_KEEP : ZEN_ABORT;
}

static int zen_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return zen_fail(error, "invalid or uninitialized Zenscrape scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        zen_outcome outcome = ZEN_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            zen_fail(&owned_error, "cannot create Zenscrape result");
            outcome = ZEN_ABORT;
        } else if (verify)
            outcome = zen_verify(ctx, key, &result, &owned_error);
        if (outcome == ZEN_ABORT) rc = -1;
        else if (br_results_push(out, &result) != 0) {
            zen_fail(&owned_error, "cannot append Zenscrape result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const zen_keywords[] = {"zenscrape"};
static br_detector zen_detector = {
    .type = 552, .version = 0, .name = "Zenscrape", .custom_name = "",
    .description = "Zenscrape is a web scraping service that provides an API to extract data from websites. "
                   "Zenscrape API keys can be used to access and scrape data from web pages.",
    .keywords = zen_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zen_scan,
};

int br_zenscrape_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zen_fail(error, "invalid Zenscrape detector output");
    *out = NULL;
    if (br_key_pattern_init(&zen_detector,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            error) != 0)
        return -1;
    *out = &zen_detector;
    return 0;
}
