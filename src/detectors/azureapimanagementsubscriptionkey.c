/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/azureapimanagementsubscriptionkey/azureapimanagementsubscriptionkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *url, *key; } subscription_patterns;
typedef struct { br_slice input; br_captures values; char *error; } subscription_urls;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;
/* Reserved for the source's errNoSuchHost identity, NOT an error-text match.
 * Its current verifyMatch never returns that sentinel. */
enum { SOURCE_NO_SUCH_HOST = 1 };

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_urls(void *user, const br_span *groups, size_t ngroups)
{
    subscription_urls *urls = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > urls->input.len)
        return fail(&urls->error, "invalid Azure API Management subscription URL capture");
    /* Source selects match[0], NOT the subdomain in capture 1. */
    br_slice url = {urls->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    return br_captures_push(&urls->values, url, true, &urls->error);
}

/* 0: ordinary result (possibly a verification error); -1: resource failure;
 * SOURCE_NO_SUCH_HOST is deliberately unreachable in this pinned verifier. */
static int verify_subscription(const br_scan_ctx *ctx, const char *base_url, const char *key, br_result *result)
{
    br_slice redact = {result->raw.data, result->raw.len}; /* URL only, not key. */
    /* http.NewRequestWithContext rejects nil context before Client.Do. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &redact, 1) != 0 ? -1 : 0;
    char url[96]; /* Source capture: https:// + at most 50 label bytes + suffix. */
    int n = snprintf(url, sizeof(url), "%s/echo/resource", base_url);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Ocp-Apim-Subscription-Key", key},
    };
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 1019};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) == 0) {
        if (response.status == 200) result->verified = true;
        else if (response.status != 401) {
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
        }
    }
    /* ALL Client.Do errors are suppressed, including DNS/cancellation. Never
     * translate their text into the source's unreachable DNS sentinel. Bodies
     * and body errors are ignored for every status. */
    /* Setter errors can be positive; never confuse them with the DNS sentinel. */
    int rc = cause && br_result_set_verification_error(result, cause, &redact, 1) != 0 ? -1 : 0;
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_subscription(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure API Management subscription scan arguments");
    const subscription_patterns *compiled = detector->state;
    if (!compiled->url || !compiled->key)
        return fail(error, "uninitialized Azure API Management subscription patterns");
    subscription_urls urls = {.input = input};
    br_captures keys = {0};
    char *regex_error = NULL;
    int rc = br_regex_each(compiled->url, input, collect_urls, &urls, &regex_error);
    if (urls.error) { free(regex_error); regex_error = urls.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, error);
    static const unsigned char colon[] = ":";
    /* First-seen unique order is one source-map order. Keep the FULL product:
     * a successful verification neither consumes keys nor stops an endpoint. */
    for (size_t u = 0; !rc && u < urls.values.len; ++u) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            if (verify) {
                bool cached = false;
                if (br_host_cache_contains(&invalid_hosts, urls.values.items[u], &cached) != 0) {
                    rc = fail(error, "wall clock unavailable checking Azure API Management subscription cache");
                    break;
                }
                if (cached) break; /* Source continue EndpointLoop; no lookup without verification. */
            }
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&urls.values, u), "url",
                                       br_captures_at(&keys, k), "key", (br_slice){colon, 1}) != 0)
                rc = fail(error, "cannot create Azure API Management subscription result");
            if (!rc && verify) {
                int checked = verify_subscription(ctx, urls.values.items[u], keys.items[k], &result);
                if (checked == SOURCE_NO_SUCH_HOST) {
                    /* Preserve the source branch without inventing a reachable
                     * DNS mapping: verify_subscription never returns this. */
                    if (br_host_cache_add(&invalid_hosts, urls.values.items[u]) != 0)
                        rc = fail(error, "cannot cache invalid Azure API Management subscription host");
                    br_result_clear(&result);
                    break;
                }
                if (checked < 0) rc = fail(error, "cannot verify Azure API Management subscription candidate");
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending Azure API Management subscription result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&urls.values);
    br_captures_clear(&keys);
    return rc;
}

static bool subscription_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static subscription_patterns patterns;
static const char *const keywords[] = {".azure-api.net"};
static const char *const key_prefixes[] = {"azure", ".azure-api.net", "subscription", "key"};
static const br_detector subscription = {
    .type = 1019, .version = 0, .name = "AzureAPIManagementSubscriptionKey", .custom_name = "",
    .description = "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_subscription, .false_positive = subscription_false_positive,
};

int br_azureapimanagementsubscriptionkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Azure API Management subscription detector output");
    *out = NULL;
    if (!patterns.url && br_regex_compile("https://([a-z0-9][a-z0-9-]{0,48}[a-z0-9])\\.azure-api\\.net",
                                         &patterns.url, error) != 0) return -1;
    if (!patterns.key && br_regex_compile_prefixed(key_prefixes, 4, "([a-zA-Z-0-9]{32})", &patterns.key, error) != 0)
        return -1;
    *out = &subscription;
    return 0;
}
