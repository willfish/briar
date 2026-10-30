/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scrapestack/scrapestack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool scrapestack_has(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!body.data || n > body.len) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int scrapestack_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void scrapestack_verify(const br_scan_ctx *ctx, const char *key, const char *url,
                       const char *payload, size_t payload_len, const char *authorization,
                       br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url,
        .body = {payload ? (const unsigned char *)payload : NULL, payload_len},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 581,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Client.Do errors stay unverified with no verification error. Body and
     * close errors are ignored; ABI1 releases every send, including failure. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        bool ok = response.status >= 200 && response.status < 300;
        /* ReadAll failure skips the status check. A non-2xx body cannot verify. */
        ok = ok && !response.body_error && (scrapestack_has(response.body, "html") || scrapestack_has(response.body, "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""));
        result->verified = ok;
    }
    (void)key;
    br_http_release(ctx, &response);
    free(transport_error);
    (void)authorization;
}

static int scrapestack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return scrapestack_fail(error, "invalid or uninitialized ScrapeStack scan");
    size_t original = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* Duplicates remain. The captured alphabet makes TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        const char *key = keys.items[i];
        const char *url = NULL;
        const char *payload = NULL;
        size_t payload_len = 0;
        char *authorization = NULL;
        char url_buf[256];
        if (verify) {
            int n = snprintf(url_buf, sizeof(url_buf), "https://api.scrapestack.com/scrape?access_key=%s&url=https://apple.com", key);
            if (n < 0 || (size_t)n >= sizeof(url_buf)) {
                rc = scrapestack_fail(&owned, "cannot build ScrapeStack URL");
                break;
            }
            url = url_buf;
            /* Nil context is the reachable NewRequestWithContext error and skips
             * this candidate after URL, body and Basic construction. */
            if (!ctx) {
                free(authorization);
                authorization = NULL;
                continue;
            }
        }
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = scrapestack_fail(&owned, "cannot create ScrapeStack result");
        else if (verify)
            scrapestack_verify(ctx, key, url, payload, payload_len, authorization, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = scrapestack_fail(&owned, "cannot append ScrapeStack result");
        br_result_clear(&result);
        free(authorization);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const scrapestack_keywords[] = {"scrapestack"};
static br_detector scrapestack_detector = {
    .type = 581, .version = 0, .name = "ScrapeStack", .custom_name = "",
    .description = "ScrapeStack is a web scraping API service. ScrapeStack API keys can be used to scrape web data and access various scraping functionalities.",
    .keywords = scrapestack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scrapestack_scan,
};

int br_scrapestack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return scrapestack_fail(error, "invalid ScrapeStack detector output");
    *out = NULL;
    if (!scrapestack_detector.state && br_regex_compile_prefixed(scrapestack_keywords, 1,
            "\\b([a-z0-9]{32})\\b", (br_regex **)&scrapestack_detector.state, error) != 0)
        return -1;
    *out = &scrapestack_detector;
    return 0;
}
