/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/jiratoken/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "host_cache.h"
#include "jiratoken_url.h"
#include "json.h"
#include "email_pattern.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <ctype.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const jira_keywords[] = {"atlassian", "confluence", "jira"};
static const char jira_cloud_host[] = "api.atlassian.com";
static const char jira_cloud_endpoint[] = "https://api.atlassian.com";
static const char jira_query[] = "{\"query\":\"query verify { me { user { name } } }\"}";
static const char jira_rotation[] = "https://howtorotate.com/docs/tutorials/atlassian/";
static const char *const jira_suffixes[] = {"atlassian.net", "atlassian.com", "jira.com"};
static const char jira_data_type[] =
    "struct { Me struct { User struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"user\\\"\" } \"json:\\\"me\\\"\" }";
static const char jira_me_type[] =
    "struct { User struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"user\\\"\" }";
static const char jira_user_type[] = "struct { Name string \"json:\\\"name\\\"\" }";
static br_host_cache jira_invalid_hosts = BR_HOST_CACHE_INIT;

/* The verdict stays local until after release. Tests observe that order. */
#ifndef JIRA_BEFORE_RELEASE
#define JIRA_BEFORE_RELEASE(result) ((void)(result))
#endif

typedef struct { br_regex *token, *domain, *email; } jira_patterns;
typedef struct { char *text; size_t len; } jira_text;

static int jira_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int jira_text_cmp(const void *left, const void *right)
{
    return strcmp(((const jira_text *)left)->text, ((const jira_text *)right)->text);
}

static bool jira_same(br_slice value, const char *text)
{
    size_t len = strlen(text);
    return value.len == len && value.data && !memcmp(value.data, text, len);
}

static bool jira_has(const br_captures *values, const char *text)
{
    for (size_t i = 0; values && i < values->len; ++i)
        if (jira_same(br_captures_at(values, i), text)) return true;
    return false;
}

/* Lowercase a copy and trim one trailing dot. Keep the caller's original text. */
static int jira_atlassian(br_slice host, bool *matched, char **error)
{
    char *folded = malloc(host.len + 1);
    *matched = false;
    if (!folded) return jira_fail(error, "cannot fold JiraToken host");
    for (size_t i = 0; i < host.len; ++i)
        folded[i] = (char)tolower((unsigned char)host.data[i]);
    size_t len = host.len;
    if (len && folded[len - 1] == '.') folded[--len] = '\0';
    else folded[len] = '\0';
    for (size_t i = 0; i < sizeof(jira_suffixes) / sizeof(jira_suffixes[0]); ++i) {
        size_t suffix = strlen(jira_suffixes[i]);
        bool exact = len == suffix && !memcmp(folded, jira_suffixes[i], suffix);
        bool dotted = len > suffix && folded[len - suffix - 1] == '.' &&
                      !memcmp(folded + len - suffix, jira_suffixes[i], suffix);
        if (exact || dotted) *matched = true;
    }
    free(folded);
    return 0;
}

static int jira_found_hosts(const br_captures *domains, br_captures *found, char **error)
{
    jira_text *ordered = NULL;
    size_t count = 0;
    int rc = 0;
    if (domains->len && !(ordered = calloc(domains->len, sizeof(*ordered))))
        return jira_fail(error, "cannot sort JiraToken hosts");
    for (size_t i = 0; i < domains->len; ++i) {
        bool matched = false;
        br_slice domain = br_captures_at(domains, i);
        if (jira_atlassian(domain, &matched, error) != 0) { rc = -1; break; }
        if (matched) ordered[count++] = (jira_text){domains->items[i], domain.len};
    }
    if (rc == 0 && count) qsort(ordered, count, sizeof(*ordered), jira_text_cmp);
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        br_slice host = {(const unsigned char *)ordered[i].text, ordered[i].len};
        if (br_captures_push(found, host, false, error) != 0) rc = -1;
    }
    free(ordered);
    return rc;
}

static int jira_reduce_hosts(const br_endpoint_list *endpoints, const br_captures *found,
                             br_captures *hosts, char **error)
{
    bool drop_cloud = found->len && !jira_has(found, jira_cloud_host);
    for (size_t i = 0; i < endpoints->len; ++i) {
        br_bytes reduced = {0};
        br_slice endpoint = {(const unsigned char *)endpoints->items[i], strlen(endpoints->items[i])};
        if (br_jiratoken_endpoint_host(endpoint, &reduced, error) != 0) return -1;
        bool empty = !reduced.len;
        bool cloud = jira_same((br_slice){reduced.data, reduced.len}, jira_cloud_host);
        int rc = 0;
        if (!empty && !(drop_cloud && cloud))
            rc = br_captures_push(hosts, (br_slice){reduced.data, reduced.len}, true, error) == 0 ? 0 : -1;
        free(reduced.data);
        if (rc != 0) return -1;
    }
    return 0;
}

static int jira_add_part(br_json *object, const char *name, br_slice value, char **error)
{
    if (value.len > INT_MAX) return jira_fail(error, "JiraToken secret part too large");
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part) return jira_fail(error, "cannot create JiraToken secret part");
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return jira_fail(error, "cannot store JiraToken secret part");
    }
    return 0;
}

static int jira_build(br_result *result, const br_detector *detector, br_slice email,
                      br_slice token, br_slice host, char **error)
{
    if (email.len > SIZE_MAX - token.len - host.len - 2)
        return jira_fail(error, "JiraToken RawV2 too large");
    if (br_finding_key_bytes(result, detector->type, token, "token") != 0)
        return jira_fail(error, "cannot create JiraToken result");
    size_t len = email.len + token.len + host.len + 2;
    if (!(result->raw_v2.data = malloc(len + 1)))
        return jira_fail(error, "cannot create JiraToken RawV2");
    size_t at = 0;
    if (email.len) memcpy(result->raw_v2.data + at, email.data, email.len);
    at += email.len;
    result->raw_v2.data[at++] = ':';
    if (token.len) memcpy(result->raw_v2.data + at, token.data, token.len);
    at += token.len;
    result->raw_v2.data[at++] = ':';
    if (host.len) memcpy(result->raw_v2.data + at, host.data, host.len);
    result->raw_v2.data[len] = '\0';
    result->raw_v2.len = len;
    if (jira_add_part(result->secret_parts, "domain", host, error) != 0 ||
        jira_add_part(result->secret_parts, "email", email, error) != 0) return -1;
    result->extra_data = json_object_new_object();
    char version[16];
    int formatted = snprintf(version, sizeof(version), "%d", detector->version);
    if (formatted < 0 || (size_t)formatted >= sizeof(version))
        return jira_fail(error, "cannot format JiraToken version");
    br_json *guide = json_object_new_string(jira_rotation);
    br_json *version_value = json_object_new_string(version);
    if (!result->extra_data || !guide || !version_value) {
        json_object_put(guide);
        json_object_put(version_value);
        return jira_fail(error, "cannot create JiraToken metadata");
    }
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        json_object_put(version_value);
        return jira_fail(error, "cannot store JiraToken metadata");
    }
    if (json_object_object_add(result->extra_data, "version", version_value) != 0) {
        json_object_put(version_value);
        return jira_fail(error, "cannot store JiraToken metadata");
    }
    return 0;
}

static int jira_apply_error(br_result *result, const char *cause, br_slice token,
                            bool call, char **error)
{
    /* NULL cause is a checked no-op, but v1 still calls when an error is present. */
    if (!call) return 0;
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return jira_fail(error, "cannot record JiraToken verification error");
    return 0;
}

typedef struct { char *cause; size_t name_len; } jira_proj;

static int jira_type(jira_proj *proj, br_json *value, const char *field, const char *expected)
{
    if (proj->cause) return 0; /* First ordinary mismatch sticks. Keep visiting. */
    int rc = br_json_type_cause(value, field, expected, &proj->cause);
    return rc == 0 ? 0 : rc;
}

static int jira_name(jira_proj *proj, br_json *value)
{
    if (!value) return 0; /* JSON null does not clear a string. */
    if (!json_object_is_type(value, json_type_string))
        return jira_type(proj, value, ".data.me.user.name", "string");
    proj->name_len = br_json_text(value).len; /* A later empty string does clear. */
    return 0;
}

static int jira_user_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (!br_json_field_name(name, "name")) return 0;
    return jira_name(user, value);
}

static int jira_struct(jira_proj *proj, br_json *value, br_slice encoded, const char *field,
                       const char *expected, br_json_member_fn visit)
{
    if (!value) return 0; /* JSON null does not clear a struct. */
    if (!json_object_is_type(value, json_type_object)) return jira_type(proj, value, field, expected);
    /* Duplicate objects merge in source order, even after a sticky type error. */
    return br_json_each_member(encoded, visit, proj);
}

static int jira_me_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    if (!br_json_field_name(name, "user")) return 0;
    return jira_struct(user, value, encoded, ".data.me.user", jira_user_type, jira_user_member);
}

static int jira_data_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    if (!br_json_field_name(name, "me")) return 0;
    return jira_struct(user, value, encoded, ".data.me", jira_me_type, jira_me_member);
}

static int jira_root_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    if (!br_json_field_name(name, "data")) return 0;
    return jira_struct(user, value, encoded, "JIRAGraphQLResponse.data", jira_data_type, jira_data_member);
}

/* 0 when the walk finished, including a sticky ordinary type error. Nonzero is fatal. */
static int jira_project(br_slice document, br_json *root, bool *verified, char **error)
{
    jira_proj proj = {0};
    int rc = 0;
    *verified = false;
    if (!root || json_object_is_type(root, json_type_null)) rc = 0;
    else if (!json_object_is_type(root, json_type_object))
        rc = jira_type(&proj, root, NULL, "jiratoken.JIRAGraphQLResponse");
    else rc = br_json_each_member(document, jira_root_member, &proj);
    if (rc != 0) {
        free(proj.cause);
        return jira_fail(error, "cannot project JiraToken response");
    }
    *verified = !proj.cause && proj.name_len > 0;
    free(proj.cause);
    return 0;
}

static int jira_status(const br_http_response *response, bool *verified, bool *error_present,
                       const char **cause, char *status_error, size_t status_cap, char **error)
{
    *verified = false;
    *error_present = false;
    *cause = NULL;
    if (response->status == 200) {
        br_json *root = NULL;
        size_t end = 0;
        char *decode_cause = NULL;
        /* Pass the read error through. A completed object still decodes. */
        int decoded = br_json_first_document(response->body, response->body_error, &root, &end, &decode_cause);
        if (decoded < 0) {
            free(decode_cause);
            json_object_put(root);
            return jira_fail(error, "cannot decode JiraToken response");
        }
        /* Ordinary syntax failure is unverified and nil. Do not surface the read error. */
        if (decoded == 0) {
            int rc = jira_project((br_slice){response->body.data, end}, root, verified, error);
            free(decode_cause);
            json_object_put(root);
            return rc;
        }
        free(decode_cause);
        json_object_put(root);
        return 0;
    }
    if (response->status == 401 || response->status == 403) return 0;
    if (response->status == 429 || response->status >= 500) {
        int formatted = snprintf(status_error, status_cap, "unexpected status code: %d", response->status);
        if (formatted < 0 || (size_t)formatted >= status_cap)
            return jira_fail(error, "cannot format JiraToken status");
        *cause = status_error;
        *error_present = true;
    }
    return 0;
}

static int jira_verify(const br_detector *detector, const br_scan_ctx *ctx, br_slice email,
                       br_slice token, br_slice host, br_result *result, char **error)
{
    br_jiratoken_target target = {0};
    char *authorization = NULL, *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool no_such_host = false;
    int rc = br_jiratoken_target_init(host, ctx != NULL, &target, error);
    if (rc != 0) return -1;
    /* Constructor rejection, including nil Context, is ordinary. Do not send
     * and do not classify it as no such host, even if that phrase is present. */
    if (target.cause) {
        rc = jira_apply_error(result, target.cause, token, true, error);
        br_jiratoken_target_clear(&target);
        return rc;
    }
    if (br_http_basic_auth(email, token, &authorization, error) != 0) {
        br_jiratoken_target_clear(&target);
        return jira_fail(error, "cannot construct JiraToken basic auth");
    }
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = target.url, .headers = headers, .nheaders = 3,
        .body = {(const unsigned char *)jira_query, sizeof(jira_query) - 1},
        .profile = BR_HTTP_DETECTOR_LOCAL, .detector_type = detector->type,
    };
    br_http_response response = {0};
    bool verified = false, error_present = false;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* A NULL Do cause stays NULL. Error presence still calls the v1 setter. */
        error_present = true;
        no_such_host = target.error_url_has_no_host ||
                       (send_error && strstr(send_error, "no such host"));
        cause = no_such_host ? "no such host" : send_error;
    } else if (jira_status(&response, &verified, &error_present, &cause, status_error,
                           sizeof(status_error), error) != 0) {
        rc = -1;
    }
    /* Branch and any reached status text are fixed. URL, headers, body and token stay alive. */
    JIRA_BEFORE_RELEASE(result);
    br_http_release(ctx, &response);
    if (rc == 0) result->verified = verified;
    if (rc == 0 && no_such_host && detector->version == 1 &&
        br_host_cache_add(&jira_invalid_hosts, (const char *)host.data) != 0)
        rc = jira_fail(error, "cannot cache JiraToken host");
    if (rc == 0)
        rc = jira_apply_error(result, cause, token, detector->version != 1 || error_present, error);
    br_jiratoken_target_clear(&target);
    free(send_error);
    free(authorization);
    return rc;
}

static size_t jira_encode_rune(uint32_t rune, unsigned char *out)
{
    size_t width = rune <= 0x7f ? 1 : rune <= 0x7ff ? 2 : rune <= 0xffff ? 3 : 4;
    if (width == 1) out[0] = (unsigned char)rune;
    else {
        uint32_t rest = rune;
        for (size_t i = width - 1; i > 0; --i) {
            out[i] = (unsigned char)(0x80 | (rest & 0x3f));
            rest >>= 6;
        }
        out[0] = (unsigned char)((width == 2 ? 0xc0 : width == 3 ? 0xe0 : 0xf0) | rest);
    }
    return width;
}

/* strings.ToLower on the capture only. A mapping can shrink; callers must
 * keep the encoded length rather than the source length or strlen. */
static int jira_fold_email(br_slice email, br_slice *out, char **error)
{
    *out = (br_slice){0};
    if (email.len > (SIZE_MAX - 1) / 4) return jira_fail(error, "cannot fold JiraToken email");
    unsigned char *folded = calloc(email.len * 4 + 1, 1);
    if (!folded) return jira_fail(error, "cannot fold JiraToken email");
    size_t used = 0;
    for (size_t at = 0; at < email.len;) {
        uint32_t rune = 0;
        size_t width = br_utf8_rune((br_slice){email.data + at, email.len - at}, &rune);
        if (!width) {
            free(folded);
            return jira_fail(error, "cannot fold JiraToken email");
        }
        used += jira_encode_rune(br_go_unicode_lower(rune), folded + used);
        at += width;
    }
    *out = (br_slice){folded, used};
    return 0;
}

static int jira_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return jira_fail(error, "invalid or uninitialized JiraToken scan");
    const jira_patterns *patterns = detector->state;
    if (!patterns->token || !patterns->domain || !patterns->email)
        return jira_fail(error, "invalid or uninitialized JiraToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0}, domains = {0}, raw_emails = {0}, emails = {0}, found = {0}, hosts = {0};
    br_endpoint_list endpoints = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->email, input, &raw_emails, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < raw_emails.len; ++i) {
        br_slice folded = {0};
        if (jira_fold_email(br_captures_at(&raw_emails, i), &folded, &owned_error) != 0 ||
            br_captures_push(&emails, folded, true, &owned_error) != 0) rc = -1;
        free((void *)folded.data);
    }
    if (rc == 0) rc = jira_found_hosts(&domains, &found, &owned_error);
    if (rc == 0) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, jira_cloud_endpoint,
                                           &found, &endpoints, &owned_error);
    if (rc == 0) rc = jira_reduce_hosts(&endpoints, &found, &hosts, &owned_error);
    for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
        for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
            for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
                br_slice host = br_captures_at(&hosts, h);
                br_result result = {0};
                bool cached = false, verified = false;
                if (detector->version == 1 &&
                    br_host_cache_contains(&jira_invalid_hosts, (const char *)host.data, &cached) != 0) {
                    rc = jira_fail(&owned_error, "cannot read JiraToken host cache");
                } else if (cached) {
                    continue;
                } else if (jira_build(&result, detector, br_captures_at(&emails, e),
                                      br_captures_at(&tokens, t), host, &owned_error) != 0) {
                    rc = -1;
                } else if (verify && jira_verify(detector, ctx, br_captures_at(&emails, e),
                                                 br_captures_at(&tokens, t), host, &result, &owned_error) != 0) {
                    rc = -1;
                } else {
                    /* Push moves the result, so remember verification before it. */
                    verified = result.verified;
                    if (br_results_push(out, &result) != 0)
                        rc = jira_fail(&owned_error, "cannot append JiraToken result");
                }
                br_result_clear(&result);
                if (rc == 0 && verified) break;
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_endpoint_list_clear(&endpoints);
    br_captures_clear(&hosts);
    br_captures_clear(&found);
    br_captures_clear(&emails);
    br_captures_clear(&raw_emails);
    br_captures_clear(&domains);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static jira_patterns jira_v1_patterns, jira_v2_patterns;
static const br_detector jira_v1 = {
    .type = 120, .version = 1, .name = "JiraToken", .custom_name = "",
    .description = "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate and interact with Jira's API.",
    .keywords = jira_keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &jira_v1_patterns, .scan = jira_scan,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = jira_cloud_endpoint,
};
static const br_detector jira_v2 = {
    .type = 120, .version = 2, .name = "JiraToken", .custom_name = "",
    .description = "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate API requests.",
    .keywords = jira_keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &jira_v2_patterns, .scan = jira_scan,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = jira_cloud_endpoint,
};

static int jira_init(const br_detector *detector, jira_patterns *patterns, bool prefixed,
                     const char *token, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return jira_fail(error, "invalid JiraToken detector output");
    *out = NULL;
    const char *domain = "\\b((?:[a-zA-Z0-9-]{1,24}\\.)+[a-zA-Z0-9-]{2,24}\\.[a-zA-Z0-9-]{2,16})\\b";
    if (prefixed) {
        if (!patterns->token && br_regex_compile_prefixed(jira_keywords, 3, token, &patterns->token, error) != 0)
            return -1;
        if (!patterns->domain && br_regex_compile_prefixed(jira_keywords, 3, domain, &patterns->domain, error) != 0)
            return -1;
        if (!patterns->email && br_regex_compile_prefixed(jira_keywords, 3, br_email_pattern, &patterns->email, error) != 0)
            return -1;
    } else {
        if (!patterns->token && br_regex_compile(token, &patterns->token, error) != 0) return -1;
        if (!patterns->domain && br_regex_compile(domain, &patterns->domain, error) != 0) return -1;
        if (!patterns->email && br_regex_compile(br_email_pattern, &patterns->email, error) != 0) return -1;
    }
    *out = detector;
    return 0;
}

int br_jiratoken_v1_init(const br_detector **out, char **error)
{
    return jira_init(&jira_v1, &jira_v1_patterns, true, "\\b([a-zA-Z-0-9]{24})\\b", out, error);
}

int br_jiratoken_v2_init(const br_detector **out, char **error)
{
    return jira_init(&jira_v2, &jira_v2_patterns, false, "\\b(ATATT[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\\b", out, error);
}
