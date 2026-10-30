/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newsapi/newsapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    NEWSAPI_ABORT = -1,
    NEWSAPI_KEEP = 0,
    NEWSAPI_DROP = 1
} newsapi_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* DROP is only the nil-context constructor failure. It is not an attempt. */
static newsapi_outcome verify_newsapi(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return NEWSAPI_DROP;
    static const char prefix[] =
        "https://newsapi.org/v2/everything?q=Apple&from=2021-09-29&sortBy=popularity&apiKey=";
    char url[sizeof(prefix) + 32];
    _Static_assert(sizeof(url) == sizeof(prefix) + 32, "Newsapi URL holds the raw 32-byte key");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    url[sizeof(prefix) - 1 + 32] = '\0';
    const br_http_request request = {
        .method = "GET",
        .url = url,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    /* Status is captured before release clears it. Source never reads the body,
     * so body_error cannot suppress 2xx. No setter and no error-text class. */
    int status = response.status;
    br_http_release(ctx, &response);
    free(send_error);
    if (sent == 0 && status >= 200 && status < 300) result->verified = true;
    return NEWSAPI_KEEP;
}

static int scan_newsapi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Newsapi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keep every in-range match, including duplicates. A second copy missed by
     * the upstream test is prefix consumption, not a uniqueness map. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        newsapi_outcome outcome = NEWSAPI_KEEP;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Newsapi finding");
            outcome = NEWSAPI_ABORT;
        } else if (verify)
            outcome = verify_newsapi(ctx, key, &result);
        if (outcome == NEWSAPI_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Newsapi finding");
            outcome = NEWSAPI_ABORT;
        }
        br_result_clear(&result);
        if (outcome == NEWSAPI_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"newsapi"};
static br_detector newsapi = {
    .type = 207,
    .version = 0,
    .name = "Newsapi",
    .custom_name = "",
    .description = "NewsAPI provides access to news articles from various sources. NewsAPI keys can be used to query and retrieve news data.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_newsapi,
};

int br_newsapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Newsapi detector output");
    *out = NULL;
    if (!newsapi.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{32})", &regex, error) != 0)
            return -1;
        newsapi.state = regex;
    }
    *out = &newsapi;
    return 0;
}
