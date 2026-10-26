/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/azuredirectmanagementkey/azuredirectmanagementkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;
typedef struct { br_regex *url, *key; } direct_patterns;
typedef struct { br_slice input; br_captures urls, services; char *error; } direct_urls;
/* Identity sentinel from the source, NOT an error-text classifier. Client.Do
 * errors are all suppressed, so this pinned verifier never returns it. */
enum { SOURCE_NO_SUCH_HOST = 1 };

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_urls(void *user, const br_span *groups, size_t count)
{
    direct_urls *matches = user;
    if (count < 2) return fail(&matches->error, "invalid Azure direct management URL capture count");
    for (size_t i = 0; i < 2; ++i)
        if (groups[i].begin == SIZE_MAX || groups[i].end <= groups[i].begin || groups[i].end > matches->input.len)
            return fail(&matches->error, "invalid Azure direct management URL capture");
    br_slice url = {matches->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_slice service = {matches->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    for (size_t i = 0; i < matches->urls.len; ++i)
        if (matches->urls.lengths[i] == url.len && !memcmp(matches->urls.items[i], url.data, url.len)) return 0;
    if (br_captures_push(&matches->urls, url, false, &matches->error)) return -1;
    return br_captures_push(&matches->services, service, false, &matches->error) ? -1 : 0;
}

static int authorization(const char *key, char out[192])
{
    time_t now = time(NULL);
    if (now == (time_t)-1 || (int64_t)now > INT64_MAX - 5) return -1;
    int64_t seconds = (int64_t)now + 5;
    time_t expires = (time_t)seconds;
    struct tm utc;
    if ((int64_t)expires != seconds || !gmtime_r(&expires, &utc)) return -1;
    int64_t year = (int64_t)utc.tm_year + 1900;
    if (year < 0 || year > 9999) return -1;
    char expiry[29], canonical[48];
    int n = snprintf(expiry, sizeof(expiry), "%04" PRId64 "-%02d-%02dT%02d:%02d:%02d.0000000Z",
                     year, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec);
    if (n != 28) return -1;
    n = snprintf(canonical, sizeof(canonical), "integration\n%s", expiry);
    if (n < 0 || (size_t)n >= sizeof(canonical)) return -1;
    unsigned char digest[64];
    size_t count = 0;
    /* The ENCODED ASCII key is the HMAC key. Do not Base64-decode or impose
     * padding validity beyond the source's 86..88-byte capture pattern. */
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA512", NULL, key, strlen(key),
                   (const unsigned char *)canonical, (size_t)n, digest, sizeof(digest), &count) || count != 64) return -1;
    char signature[89];
    if (EVP_EncodeBlock((unsigned char *)signature, digest, 64) != 88) return -1;
    n = snprintf(out, 192, "SharedAccessSignature uid=integration&ex=%s&sn=%s", expiry, signature);
    return n > 0 && n < 192 ? 0 : -1;
}

static int set_cause(br_result *result, const char *cause)
{
    br_slice redact = {result->raw.data, result->raw.len}; /* FULL URL only. */
    /* The core setter returns positive 1 on OOM. Never mistake that for the
     * source's unreachable DNS identity sentinel and populate its cache. */
    return br_result_set_verification_error(result, cause, &redact, 1) ? -1 : 0;
}

/* 0 ordinary result; -1 resource failure. SOURCE_NO_SUCH_HOST is unreachable. */
static int verify_direct(const br_scan_ctx *ctx, const char *base, const char *service,
                           const char *key, br_result *result)
{
    char auth[192], url[384];
    if (authorization(key, auth)) return -1;
    int n = snprintf(url, sizeof(url), "%s/subscriptions/default/resourceGroups/default/providers/Microsoft.ApiManagement/service/%s/apis?api-version=2024-05-01", base, service);
    /* Service names have at most 50 bytes, and URL captures only the fixed
     * authority suffix. Both complete source wire strings fit these buffers. */
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    if (!ctx) return set_cause(result, "net/http: nil Context");
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 1024};
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (!br_http_send(ctx, &request, &response, &error)) {
        if (response.status == 200) result->verified = true;
        else if (response.status != 401) {
            char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", response.status);
            rc = set_cause(result, cause);
        }
    }
    /* ALL Client.Do errors are false/nil, including literal DNS messages,
     * cancellation and timeouts. Ignore bodies and deferred close errors. */
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_direct(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure direct management key scan arguments");
    const direct_patterns *patterns = detector->state;
    if (!patterns->url || !patterns->key) return fail(error, "uninitialized Azure direct management patterns");
    size_t original_len = out->len;
    direct_urls matches = {.input = input};
    br_captures keys = {0};
    char *regex_error = NULL;
    int rc = br_regex_each(patterns->url, input, collect_urls, &matches, &regex_error);
    if (matches.error) { free(regex_error); regex_error = matches.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, true, error);
    static const unsigned char colon[] = ":";
    /* Keep every unique URL-major/key-minor pair, even after success. No key
     * consumption, successful-endpoint break, or verification-disabled cache. */
    for (size_t u = 0; !rc && u < matches.urls.len; ++u) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            if (verify) {
                bool cached = false;
                if (br_host_cache_contains(&invalid_hosts, matches.urls.items[u], &cached)) {
                    rc = fail(error, "cannot read Azure direct management invalid-host cache"); break;
                }
                if (cached) break;
            }
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&matches.urls, u), "url",
                                       br_captures_at(&keys, k), "key", (br_slice){colon, 1}))
                rc = fail(error, "cannot create Azure direct management result");
            if (!rc && verify) {
                int checked = verify_direct(ctx, matches.urls.items[u], matches.services.items[u], keys.items[k], &result);
                if (checked == SOURCE_NO_SUCH_HOST) {
                    if (br_host_cache_add(&invalid_hosts, matches.urls.items[u])) rc = fail(error, "cannot cache Azure direct management host");
                    br_result_clear(&result);
                    break; /* Source continue EndpointLoop, deliberately unreachable. */
                }
                if (checked != 0) rc = fail(error, "cannot verify Azure direct management candidate");
            }
            if (!rc && br_results_push(out, &result)) rc = fail(error, "cannot append Azure direct management result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&matches.urls); br_captures_clear(&matches.services); br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static bool never_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector; (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static direct_patterns patterns;
static const char *const keywords[] = {".management.azure-api.net"};
static const char *const key_prefixes[] = {"azure", ".management.azure-api.net"};
static const br_detector direct = {
    .type = 1024, .version = 0, .name = "AzureDirectManagementKey", .custom_name = "",
    .description = "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_direct, .false_positive = never_false_positive,
};

int br_azuredirectmanagementkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureDirectManagementKey detector output");
    *out = NULL;
    if (!patterns.url && br_regex_compile("https://([a-z0-9][a-z0-9-]{0,48}[a-z0-9])\\.management\\.azure-api\\.net", &patterns.url, error)) return -1;
    /* Prefix dots are intentionally regex wildcards, exactly as upstream. */
    if (!patterns.key && br_regex_compile_prefixed(key_prefixes, 2, "([a-zA-Z0-9+/]{83,85}[a-zA-Z0-9]==)", &patterns.key, error)) return -1;
    *out = &direct;
    return 0;
}
