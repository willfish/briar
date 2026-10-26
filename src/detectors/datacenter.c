/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/atlassiandatacenter/common.go. */
#include "datacenter.h"
#include "json.h"

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int br_dc_token_pattern(const char *const *prefixes, size_t n, br_regex **out, char **error)
{
    return br_regex_compile_prefixed(prefixes, n,
        "\\b([MNO][A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/=]|\\z)", out, error);
}

int br_dc_url_pattern(const char *const *prefixes, size_t n, br_regex **out, char **error)
{
    return br_regex_compile_prefixed(prefixes, n,
        "(https?://[a-zA-Z0-9][a-zA-Z0-9.\\-]*(?::\\d{1,5})?)", out, error);
}

bool br_dc_is_structural_pat44(br_slice candidate)
{
    if (!candidate.data || candidate.len != 44) return false;
    for (size_t i = 0; i < candidate.len; ++i) {
        unsigned char c = candidate.data[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/')) return false;
    }
    unsigned char raw[36];
    if (EVP_DecodeBlock(raw, candidate.data, 44) != 33) return false;
    size_t colon = 0;
    while (colon < 33 && raw[colon] != ':') ++colon;
    if (!colon || colon >= 32) return false;
    for (size_t i = 0; i < colon; ++i)
        if (raw[i] < '0' || raw[i] > '9') return false;
    return true;
}

int br_dc_find_endpoints(br_slice input, const br_regex *url_pattern,
                         const br_endpoints *settings, br_endpoint_list *out, char **error)
{
    br_captures found = {0};
    br_endpoint_list resolved = {0};
    int rc = br_captures_find(url_pattern, input, &found, true, error);
    if (!rc) rc = br_endpoints_collect(settings, "", &found, &resolved, error);
    for (size_t i = 0; !rc && i < resolved.len; ++i) {
        char *url = resolved.items[i];
        size_t len = strlen(url);
        while (len && url[len - 1] == '/') url[--len] = '\0';
        rc = br_endpoint_list_push(out, url, true, error);
    }
    if (rc) br_endpoint_list_clear(out);
    br_endpoint_list_clear(&resolved);
    br_captures_clear(&found);
    return rc;
}

static bool simple_userinfo(const char *begin, const char *end)
{
    size_t colons = 0;
    for (const char *p = begin; p < end; ++p) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') continue;
        if (c == ':' && ++colons == 1) continue;
        return false;
    }
    return true;
}

int br_dc_request_url(const char *base, const char *path, const char *raw_query,
                      char **url, char **cause)
{
    *url = NULL;
    *cause = NULL;
    size_t scheme = base && !strncmp(base, "https://", 8) ? 8 :
                    base && !strncmp(base, "http://", 7) ? 7 : 0;
    if (!scheme || !path || path[0] != '/' || strchr(base, '%')) goto unsupported;
    const char *authority = base + scheme;
    size_t authority_len = strcspn(authority, "/?#");
    if (!authority_len) goto unsupported;
    for (size_t i = 0; i < authority_len; ++i)
        if ((unsigned char)authority[i] <= 32 || (unsigned char)authority[i] >= 127) goto unsupported;
    const char *at = memchr(authority, '@', authority_len);
    if (at && !simple_userinfo(authority, at)) goto unsupported;

    CURLU *parsed = curl_url();
    if (!parsed) return -1;
    char *roundtrip = NULL, *result = NULL;
    CURLUcode code = curl_url_set(parsed, CURLUPART_URL, base, CURLU_PATH_AS_IS);
    if (!code) code = curl_url_get(parsed, CURLUPART_URL, &roundtrip, CURLU_GET_EMPTY);
    if (code) goto failed;
    /* CURLU must not silently canonicalize numeric hosts, leading-zero ports,
     * userinfo or other authority bytes that Go leaves intact. */
    const char *round_authority = strstr(roundtrip, "://");
    if (!round_authority) { code = CURLUE_BAD_HOSTNAME; goto failed; }
    round_authority += 3;
    if (strcspn(round_authority, "/?#") != authority_len ||
        memcmp(round_authority, authority, authority_len)) { code = CURLUE_BAD_HOSTNAME; goto failed; }
    const char *fragment = strchr(base, '#'), *query = strchr(base, '?');
    bool empty_query = query && (!fragment || query < fragment) &&
        (query[1] == '\0' || query[1] == '#');
    code = curl_url_set(parsed, CURLUPART_PATH, path, 0);
    if (!code) code = curl_url_set(parsed, CURLUPART_QUERY,
        raw_query && *raw_query ? raw_query : empty_query ? "" : NULL, 0);
    if (!code && fragment && !fragment[1]) code = curl_url_set(parsed, CURLUPART_FRAGMENT, NULL, 0);
    if (!code) code = curl_url_get(parsed, CURLUPART_URL, &result, CURLU_GET_EMPTY);
    if (!code) {
        *url = strdup(result);
        if (!*url) code = CURLUE_OUT_OF_MEMORY;
    }
failed:
    curl_free(roundtrip);
    curl_free(result);
    curl_url_cleanup(parsed);
    if (code == CURLUE_OUT_OF_MEMORY) return -1;
    if (!code) return 0;
unsupported:
    *cause = strdup("unsupported: Data Center URL form or normalization");
    return *cause ? 1 : -1;
}

int br_dc_verify(const br_scan_ctx *ctx, br_http_profile profile, int32_t type,
                 const char *url, const char *token, bool *verified, br_json **body, char **cause)
{
    *verified = false;
    *body = NULL;
    *cause = NULL;
    size_t len = strlen(token);
    if (len > SIZE_MAX - sizeof("Bearer ")) return -1;
    char *authorization = malloc(len + sizeof("Bearer "));
    if (!authorization) return -1;
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, token, len + 1);
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = url,
        .headers = headers, .nheaders = 2, .profile = profile, .detector_type = type};
    br_http_response response = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, cause) != 0) {
        if (!*cause && !(*cause = strdup("HTTP transport failed"))) rc = -1;
    } else if (response.status == 200) {
        br_json *value = NULL;
        char *decode_cause = NULL;
        size_t end = 0;
        int decoded = br_json_first_document(response.body, response.body_error, &value, &end, &decode_cause);
        if (decoded < 0) rc = -1;
        else {
            *verified = true; /* Decode errors do not invalidate the credential. */
            if (!decoded && value && json_object_is_type(value, json_type_object)) {
                *body = value;
                value = NULL;
            }
        }
        json_object_put(value);
        free(decode_cause);
    } else if (response.status != 401) {
        char message[80];
        snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        if (!(*cause = strdup(message))) rc = -1;
    }
    br_http_release(ctx, &response);
    free(authorization);
    return rc;
}
