/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/portainertoken/portainertoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *endpoint; } portainer_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int add_part(br_result *result, const char *name, br_slice value)
{
    if (value.len > 2147483647) return -1;
    br_json *part = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!part || json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int make_portainer(br_result *result, br_slice key, br_slice endpoint)
{
    if (br_finding_key_bytes(result, 943, key, "key") != 0) return -1;
    if (add_part(result, "url", endpoint) != 0) return -1;
    if (endpoint.len > SIZE_MAX - key.len) return -1;
    result->raw_v2.len = key.len + endpoint.len;
    result->raw_v2.data = malloc(result->raw_v2.len ? result->raw_v2.len : 1);
    if (!result->raw_v2.data) return -1;
    if (key.len) memcpy(result->raw_v2.data, key.data, key.len);
    if (endpoint.len) memcpy(result->raw_v2.data + key.len, endpoint.data, endpoint.len);
    return 0;
}

/* ParseURLAndStripPathAndParams, then Path=/api/stacks. Fragment survives. */
static int request_url(br_slice endpoint, char **out, bool *valid, char **error)
{
    *out = NULL;
    *valid = false;
    br_go_url_parts parts = {0};
    br_go_url_error ordinary = {0};
    int rc = br_go_url_parse(endpoint, &parts, &ordinary, error);
    if (rc != 0) { br_go_url_clear(&parts); return -1; }
    if (ordinary.kind != BR_GO_URL_OK || endpoint.len < 7) {
        printf("\nINVALID URL\n");
        br_go_url_clear(&parts);
        return 0;
    }
    size_t scheme = endpoint.data[4] == 's' ? 8 : 7;
    size_t extra = parts.raw_fragment.len ? parts.raw_fragment.len + 1 : 0;
    size_t user = 0;
    if (parts.has_user) user = parts.raw_user.len + 1 + (parts.has_password ? parts.raw_password.len + 1 : 0) + 1;
    if (parts.host.len > SIZE_MAX - scheme - user - sizeof("/api/stacks") - extra) {
        br_go_url_clear(&parts);
        return fail(error, "Portainer URL too large");
    }
    char *url = malloc(scheme + user + parts.host.len + sizeof("/api/stacks") + extra);
    if (!url) { br_go_url_clear(&parts); return fail(error, "out of memory constructing Portainer URL"); }
    size_t at = 0;
    memcpy(url, endpoint.data, scheme);
    at = scheme;
    if (parts.has_user) {
        memcpy(url + at, parts.raw_user.data, parts.raw_user.len);
        at += parts.raw_user.len;
        if (parts.has_password) {
            url[at++] = ':';
            memcpy(url + at, parts.raw_password.data, parts.raw_password.len);
            at += parts.raw_password.len;
        }
        url[at++] = '@';
    }
    memcpy(url + at, parts.host.data, parts.host.len);
    at += parts.host.len;
    memcpy(url + at, "/api/stacks", sizeof("/api/stacks") - 1);
    at += sizeof("/api/stacks") - 1;
    if (parts.raw_fragment.len) {
        url[at++] = '#';
        memcpy(url + at, parts.raw_fragment.data, parts.raw_fragment.len);
        at += parts.raw_fragment.len;
    }
    url[at] = 0;
    br_go_url_clear(&parts);
    *out = url;
    *valid = true;
    return 0;
}

static int verify_portainer(const br_scan_ctx *ctx, const char *url, const char *key,
                            br_result *result, char **error)
{
    if (!ctx) return 1;
    const br_header headers[] = {{"X-API-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_LOCAL, .detector_type = 943,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1) == 0 ? 0 :
        fail(error, "out of memory recording Portainer verification error");
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_portainer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized PortainerToken scan");
    const portainer_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, endpoints = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(patterns->endpoint, input, &endpoints, false, &owned);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t e = 0; !rc && e < endpoints.len; ++e) {
            char *url = NULL;
            bool valid = false;
            rc = request_url(br_captures_at(&endpoints, e), &url, &valid, &owned);
            if (rc || !valid) { free(url); continue; }
            br_result result = {0};
            if (make_portainer(&result, br_captures_at(&keys, k), br_captures_at(&endpoints, e)) != 0)
                rc = fail(&owned, "out of memory creating PortainerToken result");
            else if (verify && verify_portainer(ctx, url, keys.items[k], &result, &owned) > 0) {
                br_result_clear(&result);
                free(url);
                continue;
            } else if (verify && owned) rc = -1;
            if (!rc && endpoints.len && br_results_push(out, &result) != 0)
                rc = fail(&owned, "out of memory appending PortainerToken result");
            br_result_clear(&result);
            free(url);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&endpoints);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"portainertoken"};
static portainer_patterns patterns;
static br_detector portainer = {
    .type = 943, .version = 0, .name = "PortainerToken", .custom_name = "",
    .description = "Portainer is a management UI for Docker environments. Portainer tokens can be used to authenticate and interact with the Portainer API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_portainer,
};

int br_portainertoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid PortainerToken detector output");
    *out = NULL;
    const char *const key_prefix[] = {"portainertoken"};
    const char *const endpoint_prefix[] = {"portainer"};
    if (!patterns.key && br_regex_compile_prefixed(key_prefix, 1, "\\b(ptr_[A-Za-z0-9\\/_\\-+=]{20,60})", &patterns.key, error) != 0)
        return -1;
    if (!patterns.endpoint && br_regex_compile_prefixed(endpoint_prefix, 1, "\\b(https?:\\/\\/\\S+(:[0-9]{4,5})?)\\b", &patterns.endpoint, error) != 0)
        return -1;
    *out = &portainer;
    return 0;
}
