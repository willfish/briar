/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/salesforceoauth2/salesforceoauth2.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *instance, *key, *secret; } salesforce_patterns;

static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int query_escape(const char *in, char **out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t len = strlen(in), need = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)in[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~';
        need += plain ? 1 : 3;
    }
    char *encoded = malloc(need + 1);
    if (!encoded) return -1;
    size_t at = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)in[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~';
        if (plain) encoded[at++] = (char)c;
        else {
            encoded[at++] = '%';
            encoded[at++] = hex[c >> 4];
            encoded[at++] = hex[c & 15];
        }
    }
    encoded[at] = 0;
    *out = encoded;
    return 0;
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

static int make_salesforce(br_result *result, const char *domain, const char *key, const char *secret)
{
    if (br_finding_key(result, 47, secret, "client_secret") != 0) return -1;
    if (add_part(result, "domain", domain) != 0 || add_part(result, "client_id", key) != 0) return -1;
    size_t n = strlen(domain) + 1 + strlen(key) + 1 + strlen(secret);
    result->raw_v2.data = malloc(n + 1);
    if (!result->raw_v2.data) return -1;
    snprintf((char *)result->raw_v2.data, n + 1, "%s:%s:%s", domain, key, secret);
    result->raw_v2.len = n;
    return 0;
}

typedef struct {
    char *error, *description;
    size_t error_len, description_len;
    bool ordinary;
    char *cause;
} oauth_proj;

static int oauth_note(oauth_proj *proj, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!proj->ordinary) {
        proj->ordinary = true;
        proj->cause = next;
    } else free(next);
    return 0;
}

static int oauth_copy(char **slot, size_t *len, br_slice text)
{
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*slot);
    *slot = copy;
    *len = text.len;
    return 0;
}

static int oauth_assign(oauth_proj *proj, char **slot, size_t *len, br_json *value, const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return oauth_note(proj, value, field, "string");
    return oauth_copy(slot, len, br_json_text(value));
}

static bool oauth_eq(const char *text, size_t len, const char *literal)
{
    size_t n = strlen(literal);
    return text && len == n && !memcmp(text, literal, n);
}

static bool oauth_representable(const char *text, size_t len)
{
    return !text || strlen(text) == len;
}

static int oauth_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    oauth_proj *proj = user;
    if (br_json_field_name(name, "error"))
        return oauth_assign(proj, &proj->error, &proj->error_len, value, "oauthErrorResponse.error");
    if (br_json_field_name(name, "error_description"))
        return oauth_assign(proj, &proj->description, &proj->description_len, value, "oauthErrorResponse.error_description");
    return 0;
}

static void oauth_clear(oauth_proj *proj)
{
    free(proj->error);
    free(proj->description);
    free(proj->cause);
}

/* 0 with *present records an ordinary error. *cause may be NULL. -1 is fatal. */
static int bad_request(br_http_response *response, const char **cause, char **owned, bool *present,
                        char **error)
{
    *present = false;
    if (response->body_error) {
        *present = true;
        *owned = strdup(response->body_error);
        if (!*owned) return -1;
        *cause = *owned;
        return 0;
    }
    br_json *document = NULL;
    char *decode = NULL;
    int decoded = br_json_document(response->body, &document, &decode);
    if (decoded < 0 || decoded > 1) {
        free(decode);
        json_object_put(document);
        return -1;
    }
    if (decoded == 1) {
        *present = true;
        *owned = decode;
        *cause = decode;
        json_object_put(document);
        return 0;
    }
    free(decode);
    oauth_proj proj = {0};
    int walked = 0;
    if (!document || json_object_is_type(document, json_type_null)) {
        /* JSON null is a zero oauthErrorResponse. */
    } else if (!json_object_is_type(document, json_type_object)) {
        if (oauth_note(&proj, document, NULL, "salesforceoauth2.oauthErrorResponse") != 0) walked = -1;
    } else walked = br_json_each_member(response->body, oauth_member, &proj);
    json_object_put(document);
    if (walked != 0) { oauth_clear(&proj); return -1; }
    if (proj.ordinary) {
        *present = true;
        *owned = proj.cause;
        *cause = proj.cause;
        free(proj.error);
        free(proj.description);
        return 0;
    }
    const char *oauth_error = proj.error ? proj.error : "";
    const char *description = proj.description ? proj.description : "";
    size_t error_len = proj.error ? proj.error_len : 0;
    size_t description_len = proj.description ? proj.description_len : 0;
    int rc = 0;
    if (oauth_eq(proj.error, proj.error_len, "invalid_client_id") ||
        oauth_eq(proj.error, proj.error_len, "invalid_client")) {
        /* Determinate invalid client: no verification error. Description is not projected. */
    } else if (oauth_eq(proj.error, proj.error_len, "invalid_grant")) {
        if (!oauth_representable(description, description_len))
            rc = fail(error, "unsupported: Salesforce OAuth error string is not representable");
        else {
            *owned = malloc(description_len + sizeof("verification failed: "));
            if (!*owned) rc = -1;
            else {
                memcpy(*owned, "verification failed: ", sizeof("verification failed: ") - 1);
                if (description_len) memcpy(*owned + sizeof("verification failed: ") - 1, description, description_len);
                (*owned)[sizeof("verification failed: ") - 1 + description_len] = '\0';
                *cause = *owned;
                *present = true;
            }
        }
    } else if (!oauth_representable(oauth_error, error_len) || !oauth_representable(description, description_len)) {
        rc = fail(error, "unsupported: Salesforce OAuth error string is not representable");
    } else {
        static const char prefix[] = "unexpected OAuth error: ";
        static const char sep[] = " - ";
        *owned = malloc(sizeof(prefix) - 1 + error_len + sizeof(sep) - 1 + description_len + 1);
        if (!*owned) rc = -1;
        else {
            char *at = *owned;
            memcpy(at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
            if (error_len) { memcpy(at, oauth_error, error_len); at += error_len; }
            memcpy(at, sep, sizeof(sep) - 1); at += sizeof(sep) - 1;
            if (description_len) { memcpy(at, description, description_len); at += description_len; }
            *at = '\0';
            *cause = *owned;
            *present = true;
        }
    }
    free(proj.error);
    free(proj.description);
    return rc;
}

/* 1 means errNoHost: cache the domain and abandon its remaining pairs. */
static int verify_salesforce(const br_scan_ctx *ctx, const char *domain, const char *key,
                             const char *secret, br_result *result, char **error)
{
    char url[160];
    snprintf(url, sizeof(url), "https://%s/services/oauth2/token", domain);
    char *id = NULL, *secret_escaped = NULL, *form = NULL, *owned = NULL;
    const char *cause = NULL;
    int rc = 0;
    bool error_present = false;
    if (!ctx) {
        cause = "net/http: nil Context";
        error_present = true;
    } else if (query_escape(key, &id) != 0 || query_escape(secret, &secret_escaped) != 0) {
        free(id);
        return fail(error, "out of memory encoding Salesforce form");
    } else {
        size_t n = strlen(id) + strlen(secret_escaped) + sizeof("client_id=&client_secret=&grant_type=client_credentials");
        form = malloc(n + 8);
        if (!form) rc = fail(error, "out of memory encoding Salesforce form");
        else {
            sprintf(form, "client_id=%s&client_secret=%s&grant_type=client_credentials", id, secret_escaped);
            const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
            const br_http_request request = {
                .method = "POST", .url = url, .headers = headers, .nheaders = 1,
                .body = {(const unsigned char *)form, strlen(form)},
                .profile = BR_HTTP_SANE, .detector_type = 47,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) != 0) {
                if (send_error && strstr(send_error, "no such host")) rc = 1;
                else {
                    error_present = true;
                    if (send_error) {
                        owned = strdup(send_error);
                        if (!owned) rc = fail(error, "out of memory recording Salesforce verification error");
                        else cause = owned;
                    }
                }
            } else if (response.status == 200) result->verified = true;
            else if (response.status == 400) {
                if (bad_request(&response, &cause, &owned, &error_present, error) != 0)
                    rc = error && *error ? -1 : fail(error, "out of memory recording Salesforce verification error");
            } else {
                owned = malloc(64);
                if (!owned) rc = fail(error, "out of memory recording Salesforce verification error");
                else {
                    sprintf(owned, "unexpected status code: %d", response.status);
                    cause = owned;
                    error_present = true;
                }
            }
            if (ctx) br_http_release(ctx, &response);
            free(send_error);
        }
    }
    if (!rc && error_present) {
        br_slice credential = {(const unsigned char *)secret, strlen(secret)};
        if (br_result_set_verification_error(result, cause, &credential, 1) != 0)
            rc = -1;
    }
    free(owned);
    free(form);
    free(secret_escaped);
    free(id);
    return rc;
}

static int scan_salesforce(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SalesforceOauth2 scan");
    const salesforce_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures domains = {0}, keys = {0}, secrets = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->instance, input, &domains, true, &owned);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, true, &owned);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned);
    if (!rc && (!domains.len || !keys.len || !secrets.len)) {
        br_captures_clear(&domains);
        br_captures_clear(&keys);
        br_captures_clear(&secrets);
        free(owned);
        return 0;
    }
    for (size_t d = 0; !rc && d < domains.len; ++d) {
        bool cached = false;
        if (verify && br_host_cache_contains(&invalid_hosts, domains.items[d], &cached) != 0)
            rc = fail(&owned, "cannot read Salesforce invalid-host cache");
        if (rc || cached) continue;
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            for (size_t s = 0; !rc && s < secrets.len; ++s) {
                br_result result = {0};
                if (make_salesforce(&result, domains.items[d], keys.items[k], secrets.items[s]) != 0)
                    rc = fail(&owned, "out of memory creating SalesforceOauth2 result");
                else if (verify) {
                    int checked = verify_salesforce(ctx, domains.items[d], keys.items[k], secrets.items[s], &result, &owned);
                    if (checked < 0) rc = -1;
                    else if (checked > 0) {
                        br_result_clear(&result);
                        if (br_host_cache_add(&invalid_hosts, domains.items[d]) != 0)
                            rc = fail(&owned, "cannot record Salesforce invalid host");
                        goto next_domain;
                    }
                }
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned, "out of memory appending SalesforceOauth2 result");
                br_result_clear(&result);
            }
        }
    next_domain:;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&domains);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"salesforce", "3MVG9"};
static salesforce_patterns patterns;
static br_detector salesforce = {
    .type = 47, .version = 0, .name = "SalesforceOauth2", .custom_name = "",
    .description = "Salesforce is a customer relationship management (CRM) platform that provides a suite of applications and a platform for custom development. Its APIs use OAuth 2.0, and credentials like the Consumer Key and Secret are used to grant applications access to an organization's data.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_salesforce,
};

int br_salesforceoauth2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SalesforceOauth2 detector output");
    *out = NULL;
    const char *const prefix[] = {"salesforce", "consumer", "secret"};
    if (!patterns.instance && br_regex_compile("\\b(?:https?://)?([0-9a-zA-Z\\-\\.]{1,100}\\.my\\.salesforce\\.com)\\b", &patterns.instance, error) != 0)
        return -1;
    if (!patterns.key && br_regex_compile("\\b(3MVG9[0-9a-zA-Z._+/=]{80,251})", &patterns.key, error) != 0)
        return -1;
    if (!patterns.secret && br_regex_compile_prefixed(prefix, 3, "\\b([A-Za-z0-9+/=.]{64}|[0-9]{19})\\b", &patterns.secret, error) != 0)
        return -1;
    *out = &salesforce;
    return 0;
}
