/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/openvpn/openvpn.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret, *domain; } openvpn_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int add_part(br_result *result, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part || json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int make_openvpn(br_result *result, const char *id, const char *secret)
{
    if (br_finding_key(result, 945, secret, "client_secret") != 0) return -1;
    if (add_part(result, "client_id", id) != 0) return -1;
    size_t id_len = strlen(id), secret_len = strlen(secret);
    result->raw_v2.data = malloc(id_len + secret_len ? id_len + secret_len : 1);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, id, id_len);
    memcpy(result->raw_v2.data + id_len, secret, secret_len);
    result->raw_v2.len = id_len + secret_len;
    return 0;
}

static int verify_openvpn(const br_scan_ctx *ctx, const char *domain, const char *id,
                          const char *secret, br_result *result, char **error)
{
    if (!ctx) return 1;
    char *url = NULL, *auth = NULL;
    size_t domain_len = strlen(domain);
    static const char suffix[] = "/api/beta/oauth/token";
    url = malloc(domain_len + sizeof(suffix));
    if (!url) return fail(error, "out of memory constructing OpenVPN URL");
    memcpy(url, domain, domain_len);
    memcpy(url + domain_len, suffix, sizeof(suffix));
    int rc = br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                                (br_slice){(const unsigned char *)secret, strlen(secret)}, &auth, error);
    if (rc != 0) { free(url); return -1; }
    const br_header headers[] = {{"Authorization", auth}, {"content-type", "application/x-www-form-urlencoded"}};
    const unsigned char body[] = "grant_type=client_credentials";
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 945,
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
    br_slice credential = {(const unsigned char *)secret, strlen(secret)};
    if (br_result_set_verification_error(result, cause, &credential, 1) != 0)
        rc = fail(error, "out of memory recording OpenVPN verification error");
    br_http_release(ctx, &response);
    free(send_error);
    free(auth);
    free(url);
    return rc;
}

static int scan_openvpn(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized OpenVPN scan");
    const openvpn_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures ids = {0}, secrets = {0}, domains = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->domain, input, &domains, false, &owned);
    if (!rc) rc = br_captures_find(patterns->id, input, &ids, false, &owned);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned);
    for (size_t i = 0; !rc && i < ids.len; ++i)
        for (size_t s = 0; !rc && s < secrets.len; ++s)
            for (size_t d = 0; !rc && d < domains.len; ++d) {
                br_result result = {0};
                if (make_openvpn(&result, ids.items[i], secrets.items[s]) != 0)
                    rc = fail(&owned, "out of memory creating OpenVPN result");
                else if (verify && verify_openvpn(ctx, domains.items[d], ids.items[i], secrets.items[s], &result, &owned) > 0) {
                    br_result_clear(&result);
                    continue;
                } else if (verify && owned) rc = -1;
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned, "out of memory appending OpenVPN result");
                br_result_clear(&result);
            }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    br_captures_clear(&domains);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"openvpn"};
static openvpn_patterns patterns;
static br_detector openvpn = {
    .type = 945, .version = 0, .name = "OpenVpn", .custom_name = "",
    .description = "OpenVPN is a virtual private network (VPN) solution. OpenVPN API credentials can be used to manage and configure VPN connections and settings.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_openvpn,
};

int br_openvpn_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid OpenVPN detector output");
    *out = NULL;
    const char *const prefix[] = {"openvpn"};
    if (!patterns.id && br_regex_compile_prefixed(prefix, 1, "\\b([A-Za-z0-9-]{3,40}\\.[A-Za-z0-9-]{3,40})\\b", &patterns.id, error) != 0)
        return -1;
    if (!patterns.secret && br_regex_compile("\\b([a-zA-Z0-9_-]{64,})\\b", &patterns.secret, error) != 0)
        return -1;
    if (!patterns.domain && br_regex_compile("\\b(https?://[A-Za-z0-9-]+\\.api\\.openvpn\\.com)\\b", &patterns.domain, error) != 0)
        return -1;
    *out = &openvpn;
    return 0;
}
