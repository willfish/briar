/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/atlassiandatacenter/bitbucketdatacenter/bitbucketdatacenter.go. */
#include "detectors.h"
#include "datacenter.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *secret, *url; } bitbucket_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int bitbucket_finding(br_result *result, int32_t type, br_slice secret, const char *base_url)
{
    if (br_finding_pair_bytes(result, type, secret, "secret",
                              (br_slice){(const unsigned char *)base_url, strlen(base_url)}, "url",
                              (br_slice){(const unsigned char *)":", 1}) != 0)
        return -1;
    result->extra_data = json_object_new_object();
    br_json *url = json_object_new_string(base_url);
    if (!result->extra_data || !url) {
        json_object_put(url);
        return -1;
    }
    if (json_object_object_add(result->extra_data, "URL", url) != 0) {
        json_object_put(url);
        return -1;
    }
    return 0;
}

static int verify_bitbucket(const br_scan_ctx *ctx, const char *secret,
                              const char *base_url, br_result *result)
{
    char *url = NULL, *cause = NULL;
    br_json *body = NULL;
    int built = br_dc_request_url(base_url, "/rest/api/1.0/projects", "limit=1", &url, &cause);
    int rc = built < 0 ? -1 : 0;
    if (built == 0)
        rc = br_dc_verify(ctx, BR_HTTP_DETECTOR_LOCAL, result->detector_type,
                          url, secret, &result->verified, &body, &cause);
    if (!rc) {
        /* Unsupported URL forms are candidate errors, not scan failures. Unlike
         * Jira/Confluence, Bitbucket supplies both the secret and the URL. */
        const br_slice secrets[] = {
            {(const unsigned char *)secret, strlen(secret)},
            {(const unsigned char *)base_url, strlen(base_url)},
        };
        rc = br_result_set_verification_error(result, cause, secrets, 2);
    }
    json_object_put(body); /* Bitbucket ignores the generic response map. */
    free(url);
    free(cause);
    return rc;
}

static int scan_bitbucket(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Bitbucket Data Center scan arguments");
    const bitbucket_patterns *compiled = detector->state;
    if (!compiled->secret || !compiled->url)
        return fail(error, "uninitialized Bitbucket Data Center detector");
    br_captures secrets = {0};
    br_endpoint_list endpoints = {0};
    /* The source uses a secret set. Its alphabet makes TrimSpace a no-op. */
    int rc = br_captures_find(compiled->secret, input, &secrets, true, error);
    if (!rc && secrets.len)
        rc = br_dc_find_endpoints(input, compiled->url, ctx ? ctx->endpoints : NULL, &endpoints, error);
    /* Bitbucket requires an endpoint and emits every unique secret/URL pair.
     * Do not add a token-only fallback or stop after the first verified URL. */
    for (size_t s = 0; !rc && s < secrets.len; ++s) {
        for (size_t u = 0; !rc && u < endpoints.len; ++u) {
            br_result result = {0};
            if (bitbucket_finding(&result, detector->type, br_captures_at(&secrets, s), endpoints.items[u]) != 0 ||
                (verify && verify_bitbucket(ctx, secrets.items[s], endpoints.items[u], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Bitbucket Data Center result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&secrets);
    br_endpoint_list_clear(&endpoints);
    return rc;
}

static bitbucket_patterns patterns;
static const char *const keywords[] = {"BBDC-"};
static const char *const url_prefixes[] = {"atlassian", "bitbucket"};
static const br_detector bitbucket = {
    .type = 1045, .version = 0, .name = "BitbucketDataCenter", .custom_name = "",
    .description = "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket PATs "
                   "are used to authenticate bitbucket data center(on prem) rest endpoint requests.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_bitbucket,
    .validate_endpoints = br_endpoints_validate_configured,
};

int br_bitbucketdatacenter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bitbucket Data Center detector output");
    *out = NULL;
    if (!patterns.secret &&
        br_regex_compile("\\b(BBDC-[A-Za-z0-9+/@_-]{40,50})(?:[^A-Za-z0-9+/@_-]|$)",
                          &patterns.secret, error) != 0)
        return -1;
    if (!patterns.url && br_dc_url_pattern(url_prefixes, 2, &patterns.url, error) != 0) return -1;
    *out = &bitbucket;
    return 0;
}
