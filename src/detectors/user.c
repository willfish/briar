/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/user/user.go. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "host_cache.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_error(br_result *result, const char *message, const char *token, char **error)
{
    br_slice secret = {(const unsigned char *)token, strlen(token)};
    if (br_result_set_verification_error(result, message, &secret, 1) != 0)
        return fail(error, "cannot record User verification error");
    return 0;
}

static bool host_plain(unsigned char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return true;
    return strchr("-._~!$&'()*+,;=:", c) || c == '[' || c == ']' || c == '<' || c == '>' || c == '"';
}

/* url.URL host escaping. Unreserved bytes and the encodeHost extras stay literal. */
static int escape_host(const char *host, char **out, char **error)
{
    size_t len = strlen(host), need = 0;
    for (size_t i = 0; i < len; ++i) need += host_plain((unsigned char)host[i]) ? 1 : 3;
    char *escaped = malloc(need + 1);
    if (!escaped) return fail(error, "cannot escape User host");
    size_t at = 0;
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (host_plain(c)) escaped[at++] = (char)c;
        else {
            escaped[at++] = '%';
            escaped[at++] = hex[c >> 4];
            escaped[at++] = hex[c & 15];
        }
    }
    escaped[at] = '\0';
    *out = escaped;
    return 0;
}

static int verify_user(const br_scan_ctx *ctx, const char *host, const char *token,
                       br_result *result, char **error)
{
    char *escaped = NULL;
    if (escape_host(host, &escaped, error) != 0) return -1;
    size_t host_len = strlen(host), escaped_len = strlen(escaped);
    char *url = malloc(sizeof("https://") + escaped_len + sizeof("/api/public/users/"));
    if (!url) { free(escaped); return fail(error, "cannot create User URL"); }
    sprintf(url, "https://%s/api/public/users/", escaped);
    free(escaped);
    if (!ctx) {
        free(url);
        return set_error(result, "net/http: nil Context", token, error);
    }
    if (strlen(token) != 64 || host_len > SIZE_MAX - 65) {
        free(url);
        return fail(error, "cannot format User deduplication key");
    }
    unsigned char *dedup = malloc(65 + host_len);
    char authorization[72];
    if (!dedup) { free(url); return fail(error, "cannot format User deduplication key"); }
    memcpy(dedup, token, 64);
    dedup[64] = ':';
    memcpy(dedup + 65, host, host_len);
    snprintf(authorization, sizeof(authorization), "Token %s", token);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000, .detector_type = 274,
        .dedup_key = {dedup, 65 + host_len},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        if (send_error && strstr(send_error, "no such host")) rc = 1;
        else rc = set_error(result, send_error, token, error);
    } else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && response.status != 403 && response.status != 410) {
        char message[64];
        snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        rc = set_error(result, message, token, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    free(dedup);
    free(url);
    return rc;
}

static int scan_user(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized User scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures tokens = {0}, found = {0};
    br_endpoint_list collected = {0}, hosts = {0};
    int rc = br_captures_find(patterns[0], input, &tokens, true, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &found, false, error);
    /* NULL settings follow the engine default: found endpoints are enabled. */
    if (!rc) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "", &found, &collected, error);
    for (size_t i = 0; rc == 0 && i < collected.len; ++i) {
        const char *endpoint = collected.items[i];
        if (!strncmp(endpoint, "https://", 8)) endpoint += 8;
        rc = br_endpoint_list_push(&hosts, endpoint, true, error);
    }
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        for (size_t j = 0; rc == 0 && j < hosts.len; ++j) {
            bool cached = false;
            if (br_host_cache_contains(&invalid_hosts, hosts.items[j], &cached) != 0) {
                rc = fail(error, "cannot read User invalid-host cache");
                break;
            }
            if (cached) continue;
            char *endpoint = NULL;
            br_result result = {0};
            int drop = 0;
            if (escape_host(hosts.items[j], &endpoint, error) != 0) rc = -1;
            else {
                char *url = malloc(sizeof("https://") + strlen(endpoint));
                if (!url) rc = fail(error, "cannot create User endpoint");
                else {
                    sprintf(url, "https://%s", endpoint);
                    br_slice token = br_captures_at(&tokens, i);
                    br_slice secondary = {(const unsigned char *)url, strlen(url)};
                    if (br_finding_pair_bytes(&result, detector->type, token, "key", secondary, "endpoint",
                                              (br_slice){(const unsigned char *)":", 1}) != 0)
                        rc = fail(error, "out of memory creating User result");
                    free(url);
                }
            }
            free(endpoint);
            if (rc == 0 && verify)
                drop = verify_user(ctx, hosts.items[j], tokens.items[i], &result, error);
            if (rc == 0 && drop < 0) rc = -1;
            if (rc == 0 && drop > 0) {
                if (br_host_cache_add(&invalid_hosts, hosts.items[j]) != 0)
                    rc = fail(error, "cannot store invalid User host");
            } else if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append User result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_endpoint_list_clear(&hosts);
    br_endpoint_list_clear(&collected);
    br_captures_clear(&tokens);
    br_captures_clear(&found);
    return rc == 0 ? 0 : -1;
}

static const char *const user_keywords[] = {"user.com"};
static const char *const user_prefix[] = {"user"};
static br_regex *user_patterns[2];
static br_detector user_detector = {
    .type = 274, .version = 0, .name = "User", .custom_name = "",
    .description = "User credentials can be used to authenticate and authorize actions within the User service, potentially allowing access to sensitive data and operations.",
    .keywords = user_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = user_patterns, .scan = scan_user,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};

int br_user_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid User detector output");
    *out = NULL;
    /* A set client and the no-local dedup default both use the injected transport. */
    if (!user_patterns[0] &&
        br_regex_compile_prefixed(user_prefix, 1, "\\b([A-Za-z0-9]{64})\\b", &user_patterns[0], error) != 0)
        return -1;
    if (!user_patterns[1] &&
        br_regex_compile("\\b([a-z0-9-]+\\.user\\.com)\\b", &user_patterns[1], error) != 0)
        return -1;
    *out = &user_detector;
    return 0;
}
