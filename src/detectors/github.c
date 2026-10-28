/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/github/{v1,v2}. */
#include "detectors.h"
#include "endpoints.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static const char *const v1_prefixes[] = {
    "github_token", "github_secret", "github_key", "github_api", "github_pat",
    "githubtoken", "githubsecret", "githubkey", "githubapi", "githubpat",
    "gh_token", "gh_secret", "gh_key", "gh_api", "gh_pat",
    "ghtoken", "ghsecret", "ghkey", "ghapi", "ghpat",
};
static const char *const safe_substrings[] = {
    "avatars.githubusercontent.com", "actions/", "raw.githubusercontent.com/",
    "api.github.com/repos/", "gist.github.com/", "sha256:", "github.com/",
    "pipelines.actions.githubusercontent.com/", "ghcr.io/",
};
static const char *const v1_keywords[] = {"github", "gh"};
static const char *const v2_keywords[] = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"};
static const char *const token_types[] = {
    "Personal Access Token (classic)", "OAuth Access Token",
    "GitHub App User-to-Server Token", "GitHub App Server-to-Server (installation) Token",
    "GitHub App Refresh Token", "Personal Access Token (fine-grained)",
};

static int put_text(br_json *map, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text.len ? (const char *)text.data : "", (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(map, name, value) != 0) { json_object_put(value); return -1; }
    return 0;
}
static int put_literal(br_json *map, const char *name, const char *text)
{
    return put_text(map, name, (br_slice){(const unsigned char *)text, strlen(text)});
}

/* This is deliberately a small supported URL boundary, NOT a Go URL parser.
 * Apply lazily after complete URL assembly and the nil-context constructor skip. */
static bool ascii_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static bool supported_endpoint(const char *endpoint)
{
    const unsigned char *p = (const unsigned char *)endpoint;
    if (!strncmp(endpoint, "https://", 8)) p += 8;
    else if (!strncmp(endpoint, "http://", 7)) p += 7;
    else return false;
    const unsigned char *begin = p;
    while (ascii_alnum(*p) || *p == '.' || *p == '-') ++p;
    if (p == begin) return false;
    if (*p == ':') {
        begin = ++p;
        while (*p >= '0' && *p <= '9') ++p;
        if (p == begin) return false;
    }
    if (*p == '/') {
        ++p;
        while (ascii_alnum(*p) || *p == '.' || *p == '_' || *p == '~' || *p == '/' || *p == '-') ++p;
    }
    return !*p;
}

typedef struct {
    br_json *strings[8];
    bool site_admin, type_error;
} user_response;
static const char *const user_fields[] = {"login", "type", "name", "company", "html_url", "email", "location", "ldap_dn"};

static int user_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    user_response *user = opaque;
    /* null is a no-op even after an earlier duplicate value. Type errors stick
     * while subsequent fields continue decoding, as in a typed UserRes. */
    if (!value) return 0;
    for (size_t i = 0; i < 8; ++i) {
        if (!br_json_field_name(name, user_fields[i])) continue;
        if (!json_object_is_type(value, json_type_string)) user->type_error = true;
        else {
            br_json *retained = json_object_get(value);
            if (!retained) return -1;
            json_object_put(user->strings[i]);
            user->strings[i] = retained;
        }
        return 0;
    }
    if (br_json_field_name(name, "site_admin")) {
        if (!json_object_is_type(value, json_type_boolean)) user->type_error = true;
        else user->site_admin = json_object_get_boolean(value);
    }
    return 0;
}
static bool header_name(const char *a, const char *b)
{
    if (!a) return false;
    for (; *a && *b; ++a, ++b) {
        unsigned char c = (unsigned char)*a, d = (unsigned char)*b;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (d >= 'A' && d <= 'Z') d += 'a' - 'A';
        if (c != d) return false;
    }
    return !*a && !*b;
}
static int project_header(br_json *map, const br_http_response *response, const char *header, const char *key)
{
    for (size_t i = 0; i < response->nheaders; ++i) {
        if (!header_name(response->headers[i].name, header)) continue;
        const char *value = response->headers[i].value;
        return value && *value ? put_literal(map, key, value) : 0;
    }
    return 0;
}
/* 0 typed success, 1 ordinary decode/type failure, -1 resource failure. */
static int decode_project(br_result *result, const br_http_response *response)
{
    br_json *document = NULL;
    char *cause = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &document, &end, &cause);
    free(cause);
    if (rc) { json_object_put(document); return rc < 0 ? -1 : 1; }
    user_response user = {0};
    if (document && !json_object_is_type(document, json_type_object)) rc = 1;
    else if (document) {
        rc = br_json_each_member((br_slice){response->body.data, end}, user_member, &user);
        if (!rc && user.type_error) rc = 1;
    }
    if (!rc) {
        static const char *const keys[] = {"username", "account_type", "name", "company", "url", "email", "location", "ldap_dn"};
        for (size_t i = 0; i < 8 && !rc; ++i) {
            br_slice text = br_json_text(user.strings[i]);
            if (i == 0 || i == 1 || i == 4 || text.len) rc = put_text(result->extra_data, keys[i], text);
        }
        if (!rc && user.site_admin) rc = put_literal(result->extra_data, "site_admin", "true");
        if (!rc) rc = project_header(result->extra_data, response, "X-OAuth-Scopes", "scopes");
        if (!rc) rc = project_header(result->extra_data, response, "github-authentication-token-expiration", "expiry");
    }
    for (size_t i = 0; i < 8; ++i) json_object_put(user.strings[i]);
    json_object_put(document);
    return rc;
}

static int verify_token(const br_scan_ctx *ctx, br_slice token, br_result *result,
                        char **pending, char **error)
{
    br_endpoint_list endpoints = {0};
    int rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "https://api.github.com", NULL, &endpoints, error);
    for (size_t i = 0; !rc && i < endpoints.len; ++i) {
        free(*pending); *pending = NULL;
        size_t len = strlen(endpoints.items[i]);
        if (len > SIZE_MAX - sizeof("/user")) { rc = fail(error, "GitHub endpoint too large"); break; }
        char *url = malloc(len + sizeof("/user"));
        if (!url) { rc = fail(error, "cannot allocate GitHub URL"); break; }
        memcpy(url, endpoints.items[i], len);
        memcpy(url + len, "/user", sizeof("/user"));
        if (!ctx) { free(url); continue; }
        if (!supported_endpoint(endpoints.items[i])) {
            free(url); rc = fail(error, "unsupported GitHub endpoint URL form"); break;
        }
        /* The fixed extraction grammar bounds token length to 266 bytes. */
        char authorization[sizeof("token ") + 266];
        memcpy(authorization, "token ", 6);
        memcpy(authorization + 6, token.data, token.len);
        authorization[6 + token.len] = 0;
        const br_header headers[] = {{"Content-Type", "application/json; charset=utf-8"}, {"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 8,
        };
        br_http_response response = {0};
        int sent = br_http_send(ctx, &request, &response, pending);
        if (!sent && response.status >= 200 && response.status < 300) {
            int decoded = decode_project(result, &response);
            if (decoded < 0) rc = fail(error, "cannot decode/project GitHub user response");
            else if (!decoded) result->verified = true;
        }
        /* Own URL/auth and owned cause through release. Prepared shared UA is
         * intentionally not borrowed beyond send on the ordinary ABI1 path. */
        br_http_release(ctx, &response);
        free(url);
        if (result->verified) break;
    }
    br_endpoint_list_clear(&endpoints);
    return rc;
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    bool verify;
    br_slice input;
    br_results *out;
    char **error;
} scan_state;
static int matched(void *opaque, const br_span *groups, size_t ngroups)
{
    scan_state *state = opaque;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end > state->input.len)
        return fail(state->error, "invalid GitHub capture");
    br_slice token = {state->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    if (state->detector->version == 1) {
        br_slice whole = {state->input.data + groups[0].begin, groups[0].end - groups[0].begin};
        for (size_t i = 0; i < sizeof(safe_substrings) / sizeof(*safe_substrings); ++i) {
            br_slice safe = {(const unsigned char *)safe_substrings[i], strlen(safe_substrings[i])};
            if (br_slice_find(whole, safe, 0) != SIZE_MAX) return 0;
        }
        /* The sole custom FP, "github commit", cannot occur in ASCII 40-hex.
         * Do not substitute the shared default terms or global wordlists. */
        if (br_ascii_shannon_entropy(token) < 3.5) return 0;
    }
    br_result result = {0};
    char *pending = NULL;
    int rc = br_finding_key_bytes(&result, 8, token, "key");
    if (!rc) {
        result.extra_data = json_object_new_object();
        if (!result.extra_data) rc = -1;
    }
    if (!rc) rc = put_literal(result.extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/github/");
    if (!rc) rc = put_literal(result.extra_data, "version", state->detector->version == 1 ? "1" : "2");
    if (!rc && state->detector->version == 2) {
        const char *label = "Unknown GitHub token";
        for (size_t i = 0; i < 6; ++i) {
            size_t len = strlen(v2_keywords[i]);
            if (token.len >= len && !memcmp(token.data, v2_keywords[i], len)) { label = token_types[i]; break; }
        }
        rc = put_literal(result.extra_data, "token_type", label);
    }
    if (!rc && state->verify) rc = verify_token(state->ctx, token, &result, &pending, state->error);
    if (!rc && state->verify) rc = br_result_set_verification_error(&result, pending, &token, 1);
    free(pending);
    if (!rc) rc = br_results_push(state->out, &result);
    br_result_clear(&result);
    if (rc && !*state->error) fail(state->error, "cannot construct GitHub result");
    return rc;
}
static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid GitHub scan");
    size_t original = out->len;
    char *cause = NULL;
    scan_state state = {detector, ctx, verify, input, out, &cause};
    /* The shared iterator supplies a generic callback-abort cause. Keep our
     * typed unsupported/resource failure separate so it is not overwritten. */
    char *regex_error = NULL;
    int rc = br_regex_each(detector->state, input, matched, &state, &regex_error);
    if (!cause) { cause = regex_error; regex_error = NULL; }
    free(regex_error);
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    if (error) *error = cause; else free(cause);
    return rc ? -1 : 0;
}
static br_detector v1 = {
    .type = 8, .version = 1, .name = "Github", .custom_name = "",
    .description = "GitHub is a web-based platform used for version control and collaborative software development. GitHub tokens can be used to access and modify repositories and other resources.",
    .keywords = v1_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://api.github.com",
};
static br_detector v2 = {
    .type = 8, .version = 2, .name = "Github", .custom_name = "",
    .description = "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources.",
    .keywords = v2_keywords, .nkeywords = 6,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://api.github.com",
};
int br_github_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GitHub v1 output");
    *out = NULL;
    if (!v1.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(v1_prefixes, 20, "\\b([0-9a-f]{40})\\b", &regex, error)) return -1;
        v1.state = regex;
    }
    *out = &v1; return 0;
}
int br_github_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GitHub v2 output");
    *out = NULL;
    if (!v2.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\\b", &regex, error)) return -1;
        v2.state = regex;
    }
    *out = &v2; return 0;
}
