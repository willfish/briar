/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shopifyoauth/shopifyoauth.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

static int query_escape(br_slice in, char **out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t cap = in.len * 3 + 1;
    char *text = malloc(cap ? cap : 1);
    if (!text) return -1;
    size_t at = 0;
    for (size_t i = 0; i < in.len; ++i) {
        unsigned char c = in.data[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (c == ' ') text[at++] = '+';
        else if (plain) text[at++] = (char)c;
        else {
            text[at++] = '%';
            text[at++] = hex[c >> 4];
            text[at++] = hex[c & 15];
        }
    }
    text[at] = '\0';
    *out = text;
    return 0;
}

static int add_part(br_result *result, const char *name, br_slice value)
{
    if ((!value.data && value.len) || value.len > 2147483647) return -1;
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part || json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

/* url.Values.Encode sorts keys. These three need no escaping, but still escape. */
static int form_body(br_slice client_id, br_slice secret, char **out, char **error)
{
    char *id = NULL, *sec = NULL;
    if (query_escape(client_id, &id) != 0 || query_escape(secret, &sec) != 0) {
        free(id); free(sec);
        return fail(error, "cannot encode Shopify form");
    }
    size_t n = strlen("client_id=") + strlen(id) + strlen("&client_secret=") + strlen(sec) +
               strlen("&grant_type=client_credentials");
    char *body = malloc(n + 1);
    if (!body) {
        free(id); free(sec);
        return fail(error, "cannot encode Shopify form");
    }
    memcpy(body, "client_id=", 10);
    memcpy(body + 10, id, strlen(id));
    size_t at = 10 + strlen(id);
    memcpy(body + at, "&client_secret=", 15);
    at += 15;
    memcpy(body + at, sec, strlen(sec));
    at += strlen(sec);
    memcpy(body + at, "&grant_type=client_credentials", 30);
    body[at + 30] = '\0';
    free(id); free(sec);
    *out = body;
    return 0;
}

static int verify_shopify(const br_scan_ctx *ctx, br_slice domain, br_slice client_id,
                          br_slice secret, const char *url, const char *body,
                          br_result *result, char **error)
{
    /* URL and form are already built. %w wrappers unwrap to the innermost cause. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0
            ? 0 : fail(error, "cannot set Shopify verification error");
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, strlen(body)},
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000, .detector_type = 1044,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool error_present = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        error_present = true;
        cause = send_error;
    } else if (response.status == 200) {
        result->verified = true;
    } else if (response.status != 400 && response.status != 404) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fail(error, "cannot format Shopify status");
        else {
            error_present = true;
            cause = status_error;
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = -1;
    free(send_error);
    (void)domain;
    (void)client_id;
    return rc;
}

typedef struct { br_regex *secret, *client_id, *domain; } shopify_state;

static int scan_shopify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    shopify_state *state = detector ? (shopify_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shopify OAuth scan");
    size_t before = out->len;
    br_captures secrets = {0}, ids = {0}, domains = {0};
    char *owned = NULL;
    int rc = br_captures_find(state->secret, input, &secrets, true, &owned);
    if (!rc) rc = br_captures_find(state->client_id, input, &ids, true, &owned);
    if (!rc) rc = br_captures_find(state->domain, input, &domains, true, &owned);
    if (!rc && secrets.len && ids.len && domains.len) {
        for (size_t d = 0; !rc && d < domains.len; ++d) {
            for (size_t c = 0; !rc && c < ids.len; ++c) {
                for (size_t s = 0; !rc && s < secrets.len; ++s) {
                    br_slice domain = br_captures_at(&domains, d);
                    br_slice client = br_captures_at(&ids, c);
                    br_slice secret = br_captures_at(&secrets, s);
                    char *url = NULL, *body = NULL;
                    size_t ulen = strlen("https://") + domain.len + strlen("/admin/oauth/access_token");
                    url = malloc(ulen + 1);
                    if (!url) rc = fail(&owned, "cannot format Shopify URL");
                    else {
                        memcpy(url, "https://", 8);
                        memcpy(url + 8, domain.data, domain.len);
                        memcpy(url + 8 + domain.len, "/admin/oauth/access_token", 25);
                        url[ulen] = '\0';
                    }
                    if (!rc) rc = form_body(client, secret, &body, &owned);
                    br_result result = {0};
                    if (!rc && br_finding_key_bytes(&result, detector->type, secret, "client_secret") != 0)
                        rc = fail(&owned, "cannot create Shopify finding");
                    if (!rc && (add_part(&result, "domain", domain) != 0 ||
                                add_part(&result, "client_id", client) != 0))
                        rc = fail(&owned, "cannot store Shopify secret parts");
                    if (!rc) {
                        result.raw_v2.len = domain.len + 1 + client.len + 1 + secret.len;
                        result.raw_v2.data = malloc(result.raw_v2.len ? result.raw_v2.len : 1);
                        if (!result.raw_v2.data) rc = fail(&owned, "cannot store Shopify raw");
                        else {
                            size_t at = 0;
                            if (domain.len) memcpy(result.raw_v2.data, domain.data, domain.len);
                            at = domain.len;
                            result.raw_v2.data[at++] = ':';
                            if (client.len) memcpy(result.raw_v2.data + at, client.data, client.len);
                            at += client.len;
                            result.raw_v2.data[at++] = ':';
                            if (secret.len) memcpy(result.raw_v2.data + at, secret.data, secret.len);
                        }
                    }
                    if (!rc && verify) rc = verify_shopify(ctx, domain, client, secret, url, body, &result, &owned);
                    if (!rc && br_results_push(out, &result) != 0)
                        rc = fail(&owned, "cannot append Shopify finding");
                    br_result_clear(&result);
                    free(url);
                    free(body);
                }
            }
        }
    }
    if (rc) rollback(out, before);
    br_captures_clear(&secrets);
    br_captures_clear(&ids);
    br_captures_clear(&domains);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"shpss_", "myshopify.com"};
static const char *const id_keywords[] = {"shopify", "client", "id"};
static br_detector shopify = {
    .type = 1044, .version = 0, .name = "ShopifyOAuth", .custom_name = "",
    .description = "Shopify OAuth credentials (client ID and client secret) are used to authenticate applications with Shopify stores. These credentials can be used to access store data and perform operations on behalf of the application.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_shopify,
};

int br_shopifyoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shopify OAuth detector output");
    *out = NULL;
    if (shopify.state) { *out = &shopify; return 0; }
    shopify_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Shopify patterns");
    if (br_regex_compile("\\b(shpss_[a-fA-F0-9]{32})\\b", &state->secret, error) != 0 ||
        br_regex_compile_prefixed(id_keywords, 3, "\\b([a-zA-Z0-9]{32})\\b", &state->client_id, error) != 0 ||
        br_regex_compile("\\b([a-zA-Z0-9][-a-zA-Z0-9]*\\.myshopify\\.com)\\b", &state->domain, error) != 0) {
        free(state);
        return -1;
    }
    shopify.state = state;
    *out = &shopify;
    return 0;
}
