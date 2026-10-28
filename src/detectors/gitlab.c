/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gitlab/{v1,v2,v3}. */
#include "detectors.h"
#include "endpoints.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}
static int put(br_json *map, const char *key, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(map, key, value)) { json_object_put(value); return -1; }
    return 0;
}
static bool alnum_ascii(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
/* Same deliberately bounded constructor subset as GitHub. No normalization,
 * DNS validation or numeric-port limits. Apply only to reached attempts. */
static bool supported_endpoint(const char *endpoint)
{
    const unsigned char *p = (const unsigned char *)endpoint;
    if (!strncmp(endpoint, "https://", 8)) p += 8;
    else if (!strncmp(endpoint, "http://", 7)) p += 7;
    else return false;
    const unsigned char *begin = p;
    while (alnum_ascii(*p) || *p == '.' || *p == '-') ++p;
    if (p == begin) return false;
    if (*p == ':') {
        begin = ++p;
        while (*p >= '0' && *p <= '9') ++p;
        if (p == begin) return false;
    }
    if (*p == '/') {
        ++p;
        while (alnum_ascii(*p) || *p == '.' || *p == '_' || *p == '~' || *p == '/' || *p == '-') ++p;
    }
    return !*p;
}
static int retain(br_result *result, const char *cause, char **error)
{
    /* Upstream passes NO redaction arguments, including constructor/Do errors. */
    if (br_result_set_verification_error(result, cause, NULL, 0))
        return fail(error, "cannot retain GitLab verification cause");
    return 0;
}
static int verify_token(const br_scan_ctx *ctx, const char *endpoint, br_slice token,
                        br_result *result, char **error)
{
    size_t len = strlen(endpoint);
    if (len > SIZE_MAX - sizeof("/api/v4/user")) return fail(error, "GitLab endpoint too large");
    char *url = malloc(len + sizeof("/api/v4/user"));
    if (!url) return fail(error, "cannot allocate GitLab URL");
    memcpy(url, endpoint, len);
    memcpy(url + len, "/api/v4/user", sizeof("/api/v4/user"));
    int rc = 0;
    if (!ctx) rc = retain(result, "net/http: nil Context", error);
    else if (!supported_endpoint(endpoint)) rc = fail(error, "unsupported GitLab endpoint URL form");
    /* The largest fixed pattern is v3: 6+300+4+2+4+9 UTF-8 bytes. */
    else if (token.len > 325) rc = fail(error, "invalid GitLab capture length");
    else {
        char authorization[sizeof("Bearer ") + 325];
        memcpy(authorization, "Bearer ", 7);
        memcpy(authorization + 7, token.data, token.len);
        authorization[7 + token.len] = 0;
        if (memchr(token.data, 0, token.len)) {
            free(url);
            return fail(error, "unsupported GitLab binary Authorization value");
        }
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 9,
        };
        br_http_response response = {0};
        char *cause = NULL;
        int sent = br_http_send(ctx, &request, &response, &cause);
        if (sent) rc = retain(result, cause, error);
        /* ReadAll takes precedence over EVERY status, including 401/403.
         * A non-NULL empty read cause is still an error. */
        else if (response.body_error) rc = retain(result, response.body_error, error);
        else if (response.status == 200) {
            br_json *document = NULL;
            char *decode_cause = NULL;
            int decoded = br_json_document(response.body, &document, &decode_cause);
            if (decoded < 0) rc = fail(error, "cannot validate GitLab JSON");
            else result->verified = decoded == 0;
            json_object_put(document);
            free(decode_cause);
        } else if (response.status == 403) {
            static const unsigned char blocked[] = "403 Forbidden - Your account has been blocked";
            if (br_slice_find(response.body, (br_slice){blocked, sizeof(blocked) - 1}, 0) != SIZE_MAX &&
                put(result->extra_data, "blocked", "True")) rc = fail(error, "cannot project GitLab blocked metadata");
            if (!rc) result->verified = true;
        } else if (response.status != 401) {
            char status[80];
            snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
            rc = retain(result, status, error);
        }
        /* Only provider-owned authorization and URL survive send through release. */
        br_http_release(ctx, &response);
        free(cause);
    }
    free(url);
    return rc;
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    bool verify;
    br_slice input;
    const br_endpoint_list *endpoints;
    br_results *out;
    char **error;
} scan_state;
static int matched(void *opaque, const br_span *groups, size_t ngroups)
{
    scan_state *s = opaque;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].begin > groups[1].end ||
        groups[1].end > s->input.len || groups[0].begin > groups[0].end || groups[0].end > s->input.len)
        return fail(s->error, "invalid GitLab capture");
    br_slice token = {s->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    if (s->detector->version == 1) {
        br_slice whole = {s->input.data + groups[0].begin, groups[0].end - groups[0].begin};
        if (br_slice_find(whole, (br_slice){(const unsigned char *)"glpat-", 6}, 0) != SIZE_MAX) return 0;
        if (br_ascii_shannon_entropy(token) < 3.6) return 0;
    }
    for (size_t i = 0; i < s->endpoints->len; ++i) {
        const char *endpoint = s->endpoints->items[i];
        br_result result = {0};
        int rc = br_finding_pair_bytes(&result, 9, token, "key",
            (br_slice){(const unsigned char *)endpoint, strlen(endpoint)}, "host", (br_slice){0});
        if (!rc) {
            result.extra_data = json_object_new_object();
            if (!result.extra_data) rc = -1;
        }
        if (!rc) rc = put(result.extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/gitlab/");
        if (!rc) rc = put(result.extra_data, "version", s->detector->version == 1 ? "1" : s->detector->version == 2 ? "2" : "3");
        if (!rc && s->verify) rc = verify_token(s->ctx, endpoint, token, &result, s->error);
        bool verified = result.verified;
        if (!rc) rc = br_results_push(s->out, &result);
        br_result_clear(&result);
        if (rc) return fail(s->error, "cannot construct GitLab finding");
        if (verified) break;
    }
    return 0;
}
static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid GitLab scan");
    size_t original = out->len;
    br_endpoint_list endpoints = {0};
    char *cause = NULL, *regex_error = NULL;
    int rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "https://gitlab.com", NULL, &endpoints, &cause);
    scan_state state = {detector, ctx, verify, input, &endpoints, out, &cause};
    if (!rc) rc = br_regex_each(detector->state, input, matched, &state, &regex_error);
    if (!cause) { cause = regex_error; regex_error = NULL; }
    free(regex_error);
    br_endpoint_list_clear(&endpoints);
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    if (error) *error = cause; else free(cause);
    return rc ? -1 : 0;
}
static const char *const v1_keywords[] = {"gitlab"};
static const char *const pat_keywords[] = {"glpat-"};
static br_detector versions[] = {
    {.type = 9, .version = 1, .name = "Gitlab", .custom_name = "",
     .description = "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab API tokens can be used to access and modify repository data and other resources.",
     .keywords = v1_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
     .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://gitlab.com"},
    {.type = 9, .version = 2, .name = "Gitlab", .custom_name = "",
     .description = "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab Personal Access Tokens (PATs) can be used to authenticate and access GitLab resources.",
     .keywords = pat_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
     .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://gitlab.com"},
    {.type = 9, .version = 3, .name = "Gitlab", .custom_name = "",
     .description = "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab Personal Access Tokens (PATs) can be used to authenticate and access GitLab resources.",
     .keywords = pat_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
     .scan = scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "https://gitlab.com"},
};
static int init(size_t index, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GitLab output");
    *out = NULL;
    br_detector *d = &versions[index];
    if (!d->state) {
        br_regex *regex = NULL;
        int rc = index == 0 ? br_regex_compile_prefixed(v1_keywords, 1, "\\b([a-zA-Z0-9][a-zA-Z0-9\\-=_]{19,21})\\b", &regex, error) :
            br_regex_compile(index == 1 ? "\\b(glpat-[a-zA-Z0-9\\-=_]{20,22})\\b" :
                "\\b(glpat-[a-zA-Z0-9\\-=_]{27,300}.[0-9a-z]{2}.[a-z0-9]{9})\\b", &regex, error);
        if (rc) return -1;
        d->state = regex;
    }
    *out = d;
    return 0;
}
int br_gitlab_v1_init(const br_detector **out, char **error) { return init(0, out, error); }
int br_gitlab_v2_init(const br_detector **out, char **error) { return init(1, out, error); }
int br_gitlab_v3_init(const br_detector **out, char **error) { return init(2, out, error); }
