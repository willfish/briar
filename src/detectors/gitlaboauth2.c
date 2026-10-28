/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gitlaboauth2/gitlaboauth2.go. */
#include "detectors.h"
#include "endpoints.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } patterns;
static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}
static int put(br_json *map, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(map, name, value)) { json_object_put(value); return -1; }
    return 0;
}
/* Provider-local supported constructor subset, not normalization or a DNS check. */
static bool alnum_ascii(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}
static bool supported(const char *endpoint)
{
    const unsigned char *p = (const unsigned char *)endpoint;
    if (!strncmp(endpoint, "https://", 8)) p += 8;
    else if (!strncmp(endpoint, "http://", 7)) p += 7;
    else return false;
    const unsigned char *start = p;
    while (alnum_ascii(*p) || *p == '.' || *p == '-') ++p;
    if (p == start) return false;
    if (*p == ':') {
        start = ++p;
        while (*p >= '0' && *p <= '9') ++p;
        if (p == start) return false;
    }
    if (*p == '/') {
        ++p;
        while (alnum_ascii(*p) || *p == '.' || *p == '_' || *p == '~' || *p == '/' || *p == '-') ++p;
    }
    return !*p;
}

typedef struct { br_json *value; char *cause; } error_response;
static int member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    error_response *state = opaque;
    if (!value || !br_json_field_name(name, "error")) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        /* An anonymous struct has an empty Struct name in UnmarshalTypeError. */
        if (!state->cause && br_json_type_cause(value, ".error", "string", &state->cause)) return -1;
    } else {
        br_json *retained = json_object_get(value);
        if (!retained) return -1;
        json_object_put(state->value);
        state->value = retained;
    }
    return 0;
}
/* 0 = candidate policy completed; -1 = resource/unsupported fatal. */
static int decode(br_slice body, br_result *result, char **cause, char **error)
{
    br_json *document = NULL;
    int rc = br_json_document(body, &document, cause);
    if (rc) { json_object_put(document); return rc < 0 ? fail(error, "cannot decode GitLabOauth2 JSON") : 0; }
    error_response state = {0};
    if (document && !json_object_is_type(document, json_type_object)) {
        rc = br_json_type_cause(document, NULL, "struct { Error string \"json:\\\"error\\\"\" }", &state.cause);
    } else if (document) rc = br_json_each_member(body, member, &state);
    json_object_put(document);
    if (rc) {
        json_object_put(state.value); free(state.cause);
        return fail(error, "cannot decode GitLabOauth2 typed response");
    }
    if (state.cause) *cause = state.cause;
    else {
        br_slice text = br_json_text(state.value);
        if (text.len == sizeof("invalid_scope") - 1 && !memcmp(text.data, "invalid_scope", text.len))
            result->verified = true;
        else if (memchr(text.data, 0, text.len))
            rc = fail(error, "unsupported GitLabOauth2 NUL verification diagnostic");
        else {
            static const char prefix[] = "unexpected error in response: ";
            if (text.len > SIZE_MAX - sizeof(prefix)) rc = -1;
            else *cause = malloc(sizeof(prefix) + text.len);
            if (!rc && !*cause) rc = -1;
            if (!rc) {
                memcpy(*cause, prefix, sizeof(prefix) - 1);
                memcpy(*cause + sizeof(prefix) - 1, text.data, text.len);
                (*cause)[sizeof(prefix) - 1 + text.len] = 0;
            } else if (!*error) fail(error, "cannot allocate GitLabOauth2 response cause");
        }
    }
    json_object_put(state.value);
    return rc ? -1 : 0;
}
static int verify_match(const br_scan_ctx *ctx, const char *endpoint, br_slice id,
                        br_slice secret, br_result *result, char **error)
{
    static const char prefix[] = "grant_type=client_credentials&client_id=";
    static const char middle[] = "&client_secret=";
    size_t len = strlen(endpoint);
    if (len > SIZE_MAX - sizeof("/oauth/token")) return fail(error, "GitLabOauth2 endpoint too large");
    char *url = malloc(len + sizeof("/oauth/token"));
    size_t bodylen = sizeof(prefix) - 1 + id.len + sizeof(middle) - 1 + secret.len;
    char *body = malloc(bodylen + 1);
    if (!url || !body) { free(url); free(body); return fail(error, "cannot allocate GitLabOauth2 request"); }
    memcpy(url, endpoint, len); memcpy(url + len, "/oauth/token", sizeof("/oauth/token"));
    size_t at = sizeof(prefix) - 1;
    memcpy(body, prefix, at); memcpy(body + at, id.data, id.len); at += id.len;
    memcpy(body + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(body + at, secret.data, secret.len); body[bodylen] = 0;
    char *cause = NULL;
    int rc = 0;
    /* Both complete literal strings precede context-bound construction. */
    if (!ctx) {
        cause = strdup("net/http: nil Context");
        if (!cause) rc = fail(error, "cannot allocate GitLabOauth2 constructor cause");
    } else if (!supported(endpoint)) rc = fail(error, "unsupported GitLabOauth2 endpoint URL form");
    else {
        const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 1,
            .body = {(const unsigned char *)body, bodylen}, .profile = BR_HTTP_SANE,
            .timeout_ms = 5000, .detector_type = 1050,
        };
        br_http_response response = {0};
        if (!br_http_send(ctx, &request, &response, &cause)) {
            if (response.status == 400) {
                if (response.body_error) {
                    cause = strdup(response.body_error);
                    if (!cause) rc = fail(error, "cannot allocate GitLabOauth2 read cause");
                } else rc = decode(response.body, result, &cause, error);
            } else if (response.status != 401) {
                char message[96];
                snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
                cause = strdup(message);
                if (!cause) rc = fail(error, "cannot allocate GitLabOauth2 status cause");
            }
        }
        /* URL, body, original captures and causes remain live through release.
         * Ordinary ABI1 synthesized headers/UA are not retained here. */
        br_http_release(ctx, &response);
    }
    if (!rc && br_result_set_verification_error(result, cause, NULL, 0))
        rc = fail(error, "cannot set GitLabOauth2 verification error");
    free(cause); free(url); free(body);
    return rc;
}
static int finding(br_result *r, br_slice id, br_slice secret, const char *endpoint)
{
    size_t len = strlen(endpoint);
    if (len > SIZE_MAX - id.len - secret.len) return -1;
    if (br_finding_key_bytes(r, 1050, secret, "client_secret")) return -1;
    r->raw_v2.len = id.len + secret.len + len;
    r->raw_v2.data = malloc(r->raw_v2.len);
    if (!r->raw_v2.data) return -1;
    memcpy(r->raw_v2.data, id.data, id.len);
    memcpy(r->raw_v2.data + id.len, secret.data, secret.len);
    memcpy(r->raw_v2.data + id.len + secret.len, endpoint, len);
    if (put(r->secret_parts, "client_id", id)) return -1;
    return put(r->secret_parts, "endpoint", (br_slice){(const unsigned char *)endpoint, len});
}
static int scan(const br_detector *d, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!d || !d->state || !out || (!input.data && input.len)) return fail(error, "invalid GitLabOauth2 scan");
    const patterns *p = d->state;
    br_captures ids = {0}, secrets = {0}; br_endpoint_list endpoints = {0};
    char *cause = NULL; size_t original = out->len;
    int rc = br_captures_find(p->id, input, &ids, true, &cause);
    if (!rc) rc = br_captures_find(p->secret, input, &secrets, true, &cause);
    if (!rc) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "https://gitlab.com", NULL, &endpoints, &cause);
    /* First-occurrence order is deterministic; Go's map iteration is unspecified.
     * The 1024 engine span is a hint, not a detector-local product distance cap. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        bool bound = false;
        for (size_t s = 0; !rc && !bound && s < secrets.len; ++s) {
            for (size_t e = 0; !rc && !bound && e < endpoints.len; ++e) {
                br_result r = {0};
                if (finding(&r, br_captures_at(&ids, i), br_captures_at(&secrets, s), endpoints.items[e]))
                    rc = fail(&cause, "cannot create GitLabOauth2 finding");
                if (!rc && verify) rc = verify_match(ctx, endpoints.items[e], br_captures_at(&ids, i), br_captures_at(&secrets, s), &r, &cause);
                bound = r.verified;
                if (!rc && br_results_push(out, &r)) rc = fail(&cause, "cannot append GitLabOauth2 finding");
                br_result_clear(&r);
            }
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&secrets); br_endpoint_list_clear(&endpoints);
    if (error) *error = cause; else free(cause);
    return rc ? -1 : 0;
}
static const char *const keywords[] = {"gloas-"};
static const char *const prefixes[] = {"application_id", "client_id", "app_id", "id"};
static patterns state;
static br_detector detector = {
    .type = 1050, .version = 0, .name = "GitLabOauth2", .custom_name = "",
    .description = "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab OAuth application credentials can be used to access GitLab APIs on behalf of users.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://gitlab.com",
};
int br_gitlaboauth2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GitLabOauth2 output");
    *out = NULL;
    if (!detector.state) {
        patterns p = {0};
        if (br_regex_compile_prefixed(prefixes, 4, "\\b([0-9a-f]{64})\\b", &p.id, error) ||
            br_regex_compile("\\b(gloas-[0-9a-f]{64})\\b", &p.secret, error)) {
            br_regex_free(p.id); br_regex_free(p.secret); return -1;
        }
        state = p; detector.state = &state;
    }
    *out = &detector;
    return 0;
}
