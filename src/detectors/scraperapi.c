/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scraperapi/scraperapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SCRAPER_ABORT = -1, SCRAPER_KEEP = 0, SCRAPER_SKIP = 1 } scraper_outcome;

static int scraper_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static scraper_outcome scraper_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                      char **error)
{
    /* The 32-byte lowercase capture needs no escaping. Build the complete URL
     * before NewRequestWithContext's nil-context skip. */
    char url[sizeof("https://api.scraperapi.com?api_key=&url=google.com") + 32];
    int n = snprintf(url, sizeof(url),
                     "https://api.scraperapi.com?api_key=%.*s&url=google.com",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        scraper_fail(error, "cannot format ScraperAPI URL");
        return SCRAPER_ABORT;
    }
    if (!ctx) return SCRAPER_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 15000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source assigns the shared sane client's Timeout to 15s and ignores Do
     * errors, status outside 2xx, and the body. Per-request 15s models that
     * request, not process-wide mutation or deferred Close. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return SCRAPER_KEEP;
}

static int scraper_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return scraper_fail(error, "invalid or uninitialized ScraperAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        scraper_outcome outcome = SCRAPER_KEEP;
        /* TrimSpace is a no-op for this class. Keep order and duplicates. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            scraper_fail(&owned_error, "cannot create ScraperAPI result");
            outcome = SCRAPER_ABORT;
        } else if (verify)
            outcome = scraper_verify(ctx, key, &result, &owned_error);
        if (outcome == SCRAPER_ABORT) rc = -1;
        else if (outcome == SCRAPER_KEEP && br_results_push(out, &result) != 0) {
            scraper_fail(&owned_error, "cannot append ScraperAPI result");
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

static const char *const scraper_keywords[] = {"scraperapi"};
static br_detector scraper_detector = {
    .type = 412, .version = 0, .name = "ScraperAPI", .custom_name = "",
    .description = "ScraperAPI is a service that allows users to scrape websites efficiently. "
                   "ScraperAPI keys can be used to access and scrape data from various websites.",
    .keywords = scraper_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scraper_scan,
};

int br_scraperapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return scraper_fail(error, "invalid ScraperAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&scraper_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &scraper_detector;
    return 0;
}
