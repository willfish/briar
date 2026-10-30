/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/loggly/loggly.go. */
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int loggly_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *key, *domain; } loggly_patterns;
typedef struct loggly_pending loggly_pending;
struct loggly_pending {
    loggly_pending *next;
    br_http_request request;
    br_http_response response;
    br_header header;
    char *url;
    char authorization[sizeof("Bearer ") - 1 + 36 + 1];
};

static void loggly_release(const br_scan_ctx *ctx, loggly_pending *pending)
{
    while (pending) {
        loggly_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->url);
        free(pending);
        pending = next;
    }
}

static int loggly_finding(br_result *result, int32_t type, br_slice key, br_slice domain, char **error)
{
    if (key.len != 36 || domain.len > INT_MAX || domain.len > SIZE_MAX - key.len - 1)
        return loggly_fail(error, "invalid or oversized Loggly pair");
    if (br_finding_key_bytes(result, type, key, "key") != 0)
        return loggly_fail(error, "cannot create Loggly result");
    /* The common pair helper is key-first; source RawV2 is DOMAIN:KEY. */
    result->raw_v2.len = domain.len + 1 + key.len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return loggly_fail(error, "cannot create Loggly RawV2");
    memcpy(result->raw_v2.data, domain.data, domain.len);
    result->raw_v2.data[domain.len] = ':';
    memcpy(result->raw_v2.data + domain.len + 1, key.data, key.len);
    br_json *part = json_object_new_string_len((const char *)domain.data, (int)domain.len);
    if (!part) return loggly_fail(error, "cannot create Loggly domain part");
    if (json_object_object_add(result->secret_parts, "domain", part) != 0) {
        json_object_put(part);
        return loggly_fail(error, "cannot insert Loggly domain part");
    }
    return 0;
}

static int loggly_verify(const br_scan_ctx *ctx, br_slice key, br_slice domain, br_result *result,
                          loggly_pending **pending, bool *keep, char **error)
{
    static const char prefix[] = "https://";
    static const char suffix[] = "/apiv2/customer";
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (domain.len > SIZE_MAX - overhead) return loggly_fail(error, "Loggly URL too large");
    char *url = malloc(overhead + domain.len);
    if (!url) return loggly_fail(error, "cannot construct Loggly URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain.data, domain.len);
    memcpy(url + sizeof(prefix) - 1 + domain.len, suffix, sizeof(suffix));
    /* Finding/RawV2/parts and literal URL precede NewRequestWithContext's nil
     * error; Bearer construction is not reached on that ordinary pair drop. */
    if (!ctx) {
        free(url);
        *keep = false;
        return 0;
    }
    loggly_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) {
        free(url);
        return loggly_fail(error, "cannot construct Loggly request");
    }
    *attempt = (loggly_pending){0};
    attempt->url = url;
    memcpy(attempt->authorization, "Bearer ", 7);
    memcpy(attempt->authorization + 7, key.data, key.len);
    attempt->authorization[7 + key.len] = 0;
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = url, .headers = &attempt->header, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        attempt->next = *pending;
        *pending = attempt;
        if (attempt->response.status >= 200 && attempt->response.status < 300) result->verified = true;
        else if (attempt->response.status != 401) {
            char message[96];
            int n = snprintf(message, sizeof(message), "unexpected HTTP response status %d", attempt->response.status);
            if (n < 0 || (size_t)n >= sizeof(message)) rc = loggly_fail(error, "cannot format Loggly status cause");
            else if (br_result_set_verification_error(result, message, &key, 1) != 0)
                rc = loggly_fail(error, "cannot store Loggly verification error");
        }
    } else {
        /* Preserve the WHOLE mixed preparation/Do domain, never diagnostic-text
         * provenance. Source redacts only the key, not the captured domain. */
        const char *cause = send_error ? send_error : "HTTP transport failed";
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = loggly_fail(error, "cannot store Loggly verification error");
        loggly_release(ctx, attempt); /* One ABI1 release even for failed setup. */
    }
    free(send_error);
    return rc;
}

static int loggly_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return loggly_fail(error, "invalid or uninitialized Loggly scan");
    const loggly_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    loggly_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* The independent domain scan is reached even with zero keys. */
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < domains.len; ++j) {
            br_slice domain = br_captures_at(&domains, j);
            br_result result = {0};
            bool keep = true;
            rc = loggly_finding(&result, detector->type, key, domain, &owned_error);
            if (rc == 0 && verify) rc = loggly_verify(ctx, key, domain, &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = loggly_fail(&owned_error, "cannot append Loggly result");
            br_result_clear(&result);
        }
    }
    /* Successful closes are scan-deferred LIFO after setter/publication. Keep
     * original URL/auth/key/domain values through release, never synthesized
     * prepared request/header-array/UA storage past the shared send return. */
    loggly_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&domains);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const loggly_keywords[] = {"loggly"};
static loggly_patterns loggly_compiled;
static br_detector loggly_detector = {
    .type = 944, .version = 0, .name = "Loggly", .custom_name = "",
    .description = "Loggly is a cloud-based log management service. Loggly API keys can be used to send, search, and analyze log data.",
    .keywords = loggly_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = loggly_scan,
};

int br_loggly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return loggly_fail(error, "invalid Loggly detector output");
    *out = NULL;
    if (!loggly_detector.state) {
        loggly_patterns patterns = {0};
        if (br_regex_compile_prefixed(loggly_keywords, 1,
            "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", &patterns.key, error) != 0)
            return -1;
        if (br_regex_compile("\\b([a-zA-Z0-9-]+\\.loggly\\.com)\\b", &patterns.domain, error) != 0) {
            br_regex_free(patterns.key);
            return -1;
        }
        loggly_compiled = patterns;
        loggly_detector.state = &loggly_compiled;
    }
    *out = &loggly_detector;
    return 0;
}
