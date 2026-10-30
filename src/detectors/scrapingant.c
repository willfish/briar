/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scrapingant/scrapingant.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int verify_scrapingant(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* WithTimeout panics before the URL or request exist. The 10s deadline does
     * not extend SaneHttpClient's 5s Timeout, so the request stays at 5000ms. */
    if (!ctx) return fail(error, "cannot create context from nil parent");
    if (key.len != 32) return fail(error, "invalid ScrapingAnt capture");
    static const char prefix[] = "https://api.scrapingant.com/v1/general?url=example.com&x-api-key=";
    char url[sizeof(prefix) + 32];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    url[sizeof(prefix) - 1 + 32] = '\0';
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.status == 200) verified = true;
        else if (response.status != 401 && response.status != 403) {
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
        }
    }
    /* A Do error is discarded. The setter still runs, including with a nil error. */
    int rc = set_cause(result, cause);
    if (!rc) result->verified = verified;
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? fail(error, "cannot set ScrapingAnt verification error") : 0;
}

static int scan_scrapingant(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ScrapingAnt scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create ScrapingAnt result");
        else if (verify) rc = verify_scrapingant(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append ScrapingAnt result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"scrapingant"};
static br_detector detector = {
    .type = 560, .name = "ScrapingAnt", .custom_name = "",
    .description = "ScrapingAnt is a web scraping service that provides API keys to authenticate and make requests to their scraping endpoints.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_scrapingant,
};

int br_scrapingant_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ScrapingAnt detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{32})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
