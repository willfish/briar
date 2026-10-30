/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/proxycrawl/proxycrawl.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_proxycrawl(const br_scan_ctx *ctx, const char *url, const unsigned char *dedup,
                               br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = 440, .dedup_key = {dedup, 26},
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source mutates the shared dedup client's Timeout to 10s, then suppresses
     * every DoWithDedup error. Non-2xx is unverified without a setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_proxycrawl(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ProxyCrawl scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        char url[96];
        unsigned char dedup[26];
        int n = 0;
        bool skip = false;
        if (key.len != 22 || memchr(key.data, 0, key.len))
            rc = fail(&owned, "invalid ProxyCrawl capture");
        else if (br_finding_key_bytes(&result, 440, key, "key") != 0)
            rc = fail(&owned, "cannot create ProxyCrawl result");
        else if (verify) {
            memcpy(dedup, "440:", 4);
            memcpy(dedup + 4, key.data, 22);
            n = snprintf(url, sizeof(url),
                         "https://api.proxycrawl.com/leads?token=%s&domain=slack.com", keys.items[i]);
            if (n != 78) rc = fail(&owned, "cannot format ProxyCrawl URL");
            else if (!ctx) skip = true; /* Constructor failure drops this occurrence. */
            else verify_proxycrawl(ctx, url, dedup, &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ProxyCrawl result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"proxycrawl"};
static br_detector proxycrawl = {
    .type = 440, .version = 0, .name = "ProxyCrawl", .custom_name = "",
    .description = "ProxyCrawl is a service that provides web scraping and crawling capabilities. "
                   "ProxyCrawl tokens can be used to access and control these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_proxycrawl,
};

int br_proxycrawl_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ProxyCrawl detector output");
    *out = NULL;
    if (!proxycrawl.state) {
        static const char *const prefixes[] = {"proxycrawl"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([a-zA-Z0-9_]{22})\\b", &compiled, error) != 0)
            return -1;
        proxycrawl.state = compiled;
    }
    *out = &proxycrawl;
    return 0;
}
