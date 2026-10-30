/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scraperbox/scraperbox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int scraperbox_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* False keep is the constructor continue, not an unverified finding. */
static int scraperbox_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, char **error)
{
    static const char prefix[] = "https://api.scraperbox.com/scrape?token=";
    static const char suffix[] = "&url=https://google.com";
    _Static_assert(sizeof(prefix) - 1 + 32 + sizeof(suffix) - 1 == 95, "ScraperBox URL length");
    *keep = false;
    if (key.len != 32) return scraperbox_fail(error, "invalid ScraperBox capture");
    /* The formatted URL precedes NewRequestWithContext. Nil context skips. */
    char url[96];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
    if (!ctx) return 0;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    /* Do and close errors are ignored. There is no verification-error setter. */
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int scraperbox_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return scraperbox_fail(error, "invalid or uninitialized ScraperBox scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = scraperbox_fail(&owned_error, "cannot create ScraperBox result");
        else if (verify && scraperbox_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        else if (keep && br_results_push(out, &result) != 0)
            rc = scraperbox_fail(&owned_error, "cannot append ScraperBox result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const scraperbox_keywords[] = {"scraperbox"};
static br_detector scraperbox_detector = {
    .type = 559, .version = 0, .name = "ScraperBox", .custom_name = "",
    .description = "ScraperBox is a web scraping service that allows users to extract data from websites. The provided token can be used to authenticate and perform scraping operations.",
    .keywords = scraperbox_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scraperbox_scan,
};

int br_scraperbox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return scraperbox_fail(error, "invalid ScraperBox detector output");
    *out = NULL;
    if (br_key_pattern_init(&scraperbox_detector, "\\b([A-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &scraperbox_detector;
    return 0;
}
