/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * ScrapingBee, from pinned TruffleHog pkg/detectors/scrapingbee/scrapingbee.go.
 * The prefix is a fragment, not the dispatch keyword list. Matches below
 * Shannon entropy 3.5 are ordinary skips. Duplicates collapse.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const prefix_keywords[] = {"scraping[ _-]?bee", NULL};
static const char url_prefix[] = "https://app.scrapingbee.com/api/v1/?api_key=";
static const char url_suffix[] = "&url=https://httpbin.org/anything?json&render_js=false";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[192];
    int n = snprintf(url, sizeof(url), "%s%s%s", url_prefix, key, url_suffix);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format ScrapingBee URL");
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot store ScrapingBee verification error");
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .timeout_ms = 5000, .detector_type = 139, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format ScrapingBee status error");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "cannot store ScrapingBee verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ScrapingBee scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, true, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        const char *key = found.items[i];
        if (br_ascii_shannon_entropy((br_slice){(const unsigned char *)key, strlen(key)}) < 3.5) continue;
        br_result result = {0};
        if (br_finding_key(&result, detector->type, key, "key") != 0)
            rc = fail(&owned, "cannot create ScrapingBee finding");
        else if (verify_requested && verify(ctx, key, &result, &owned) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ScrapingBee finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "ScrapingBee", .type = 139, .description =
        "ScrapingBee is a web scraping service that handles headless browsers and proxies for you. ScrapingBee API keys can be used to access and control web scraping tasks.",
    .keywords = (const char *[]){"scrapingbee", "scraping bee", "scraping-bee", "scraping_bee", NULL}, .nkeywords = 4,
    .scan = scan, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_scrapingbee_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ScrapingBee detector output");
    *out = NULL;
    if (!detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(prefix_keywords, 1, "\\b([A-Z0-9]{80})\\b", &regex, error) != 0)
            return -1;
        detector.state = regex;
    }
    *out = &detector;
    return 0;
}
