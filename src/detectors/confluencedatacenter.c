/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/atlassiandatacenter/confluencedatacenter. */
#include "detectors.h"
#include "captures.h"
#include "datacenter.h"
#include "findings.h"
#include "host_cache.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *url; } confluence_patterns;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int extra_text(br_result *result, const char *field, const char *text)
{
    result->extra_data = json_object_new_object();
    br_json *value = json_object_new_string(text);
    if (!result->extra_data || !value) { json_object_put(value); return -1; }
    if (json_object_object_add(result->extra_data, field, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int token_only(const br_detector *detector, const char *token, br_result *result)
{
    if (br_finding_key(result, detector->type, token, "token") != 0) return -1;
    result->raw_v2.data = malloc(result->raw.len);
    if (!result->raw_v2.data) return -1;
    result->raw_v2.len = result->raw.len;
    memcpy(result->raw_v2.data, result->raw.data, result->raw.len);
    return extra_text(result, "verification_note",
        "no reachable Confluence Data Center URL found in context; token reported unverified");
}

static int verify_confluence(const br_scan_ctx *ctx, const char *base, const char *token,
                              br_result *result, bool *no_host)
{
    const char suffix[] = "/rest/api/user/current";
    size_t len = strlen(base);
    if (len > SIZE_MAX - sizeof(suffix)) return -1;
    char *url = malloc(len + sizeof(suffix));
    if (!url) return -1;
    /* Source concatenation is deliberate, including paths, queries and fragments. */
    memcpy(url, base, len);
    memcpy(url + len, suffix, sizeof(suffix));
    br_json *body = NULL;
    char *cause = NULL;
    int rc = br_dc_verify(ctx, BR_HTTP_DETECTOR_LOCAL, 1047, url, token,
                          &result->verified, &body, &cause);
    if (!rc) {
        *no_host = cause && strstr(cause, "no such host");
        br_slice secret = {result->raw.data, result->raw.len};
        rc = br_result_set_verification_error(result, *no_host ? "no such host" : cause, &secret, 1);
    }
    json_object_put(body); /* This provider does not copy fields from the JSON map. */
    free(cause);
    free(url);
    return rc;
}

static int scan_confluence(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ConfluenceDataCenter scan arguments");
    const confluence_patterns *compiled = detector->state;
    if (!compiled->token || !compiled->url)
        return fail(error, "uninitialized ConfluenceDataCenter patterns");
    br_captures matches = {0}, tokens = {0};
    br_endpoint_list endpoints = {0}, live = {0};
    int rc = br_captures_find(compiled->token, input, &matches, true, error);
    for (size_t i = 0; !rc && i < matches.len; ++i) {
        br_slice token = br_captures_at(&matches, i);
        if (br_dc_is_structural_pat44(token)) rc = br_captures_push(&tokens, token, false, error);
    }
    /* Source returns before resolving endpoints if no structural PAT was found. */
    if (!rc && tokens.len)
        rc = br_dc_find_endpoints(input, compiled->url, ctx ? ctx->endpoints : NULL, &endpoints, error);
    for (size_t i = 0; !rc && i < endpoints.len; ++i) {
        bool cached = false;
        if (br_host_cache_contains(&invalid_hosts, endpoints.items[i], &cached) != 0)
            rc = fail(error, "wall clock unavailable");
        else if (!cached) rc = br_endpoint_list_push(&live, endpoints.items[i], false, error);
    }
    for (size_t k = 0; !rc && k < tokens.len; ++k) {
        bool emitted = false;
        const char *token = tokens.items[k];
        for (size_t u = 0; !rc && u < live.len; ++u) {
            const char *base = live.items[u];
            bool cached = false;
            if (br_host_cache_contains(&invalid_hosts, base, &cached) != 0) {
                rc = fail(error, "wall clock unavailable");
                break;
            }
            if (cached) continue;
            br_result result = {0};
            br_slice secret = {(const unsigned char *)token, strlen(token)};
            br_slice url = {(const unsigned char *)base, strlen(base)};
            bool no_host = false;
            if (br_finding_pair_bytes(&result, detector->type, secret, "token", url, "url",
                                      (br_slice){(const unsigned char *)":", 1}) != 0 ||
                extra_text(&result, "base_url", base) != 0 ||
                (verify && verify_confluence(ctx, base, token, &result, &no_host) != 0)) {
                br_result_clear(&result);
                rc = fail(error, "cannot create ConfluenceDataCenter result");
                break;
            }
            if (no_host && br_host_cache_add(&invalid_hosts, base) != 0) {
                br_result_clear(&result);
                rc = fail(error, "cannot store invalid Confluence URL");
                break;
            }
            /* Unlike Artifactory, emit this failure; later tokens skip the URL. */
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending ConfluenceDataCenter result");
            } else emitted = true;
        }
        if (!rc && !emitted) {
            br_result result = {0};
            if (token_only(detector, token, &result) != 0 || br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating token-only ConfluenceDataCenter result");
            }
        }
    }
    br_endpoint_list_clear(&live);
    br_endpoint_list_clear(&endpoints);
    br_captures_clear(&tokens);
    br_captures_clear(&matches);
    return rc;
}

static confluence_patterns patterns;
static const char *const keywords[] = {"confluence", "atlassian", "wiki"};
static const br_detector confluence = {
    .type = 1047, .version = 0, .name = "ConfluenceDataCenter", .custom_name = "",
    .description = "Confluence Data Center is Atlassian's self-hosted wiki product. Personal Access Tokens (PATs) "
                   "authenticate via Bearer auth against the REST API and grant access scoped to the issuing user.",
    .keywords = keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_confluence,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};

int br_confluencedatacenter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ConfluenceDataCenter detector output");
    *out = NULL;
    if (!patterns.token && br_dc_token_pattern(keywords, 3, &patterns.token, error) != 0) return -1;
    if (!patterns.url && br_dc_url_pattern(keywords, 3, &patterns.url, error) != 0) return -1;
    *out = &confluence;
    return 0;
}
