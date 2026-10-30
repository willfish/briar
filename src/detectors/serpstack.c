/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/serpstack/serpstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SERP_ABORT = -1, SERP_KEEP = 0, SERP_SKIP = 1 } serp_outcome;

static int serp_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool serp_valid_body(br_slice body)
{
    static const unsigned char search[] = "search_url";
    static const unsigned char restricted[] =
        "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
    return br_slice_find(body, (br_slice){search, sizeof(search) - 1}, 0) != SIZE_MAX ||
           br_slice_find(body, (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
}

static serp_outcome serp_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char url[sizeof("https://api.serpstack.com/search?access_key=&query=Mcdonalds") + 32];
    int n = snprintf(url, sizeof(url),
                     "https://api.serpstack.com/search?access_key=%.*s&query=Mcdonalds",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        serp_fail(error, "cannot format SerpStack URL");
        return SERP_ABORT;
    }
    if (!ctx) return SERP_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Shared client.Timeout is set to 10s. A ReadAll failure leaves the finding
     * unverified; it does not skip. Non-2xx never verifies, even with a marker. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && !response.body_error &&
        response.status >= 200 && response.status < 300)
        result->verified = serp_valid_body(response.body);
    br_http_release(ctx, &response);
    free(transport_error);
    return SERP_KEEP;
}

static int serp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return serp_fail(error, "invalid or uninitialized SerpStack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        serp_outcome outcome = SERP_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            serp_fail(&owned_error, "cannot create SerpStack result");
            outcome = SERP_ABORT;
        } else if (verify)
            outcome = serp_verify(ctx, key, &result, &owned_error);
        if (outcome == SERP_ABORT) rc = -1;
        else if (outcome == SERP_KEEP && br_results_push(out, &result) != 0) {
            serp_fail(&owned_error, "cannot append SerpStack result");
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

static const char *const serp_keywords[] = {"serpstack"};
static br_detector serp_detector = {
    .type = 561, .version = 0, .name = "SerpStack", .custom_name = "",
    .description = "SerpStack is an API service used to scrape search engine results. "
                   "SerpStack keys can be used to access and retrieve search data.",
    .keywords = serp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = serp_scan,
};

int br_serpstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return serp_fail(error, "invalid SerpStack detector output");
    *out = NULL;
    if (br_key_pattern_init(&serp_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &serp_detector;
    return 0;
}
