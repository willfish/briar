/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/artifactoryreferencetoken. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "host_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct { br_regex *token, *host; } reference_patterns;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_reference_token(const br_scan_ctx *ctx, const char *host,
                                  const char *token, br_result *result, bool *no_host)
{
    const size_t overhead = sizeof("https:///access/api/v1/tokens/me");
    size_t host_len = strlen(host);
    if (host_len > SIZE_MAX - overhead) return -1;
    char *url = malloc(host_len + overhead);
    if (!url) return -1;
    snprintf(url, host_len + overhead, "https://%s/access/api/v1/tokens/me", host);
    char authorization[sizeof("Bearer ") + 64];
    snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 1042,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    *no_host = false;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *no_host = true;
        else cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: {
            const char *content_type = "";
            /* Header.Get selects the first field, not a later successful duplicate. */
            for (size_t i = 0; i < response.nheaders; ++i) {
                if (!strcasecmp(response.headers[i].name, "Content-Type")) {
                    content_type = response.headers[i].value;
                    break;
                }
            }
            if (strstr(content_type, "application/json")) result->verified = true;
            else *no_host = true;
            break;
        }
        case 403: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Neither body reads nor deferred drain errors participate in verification. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(url);
    return rc;
}

static int scan_reference_token(const br_detector *detector, const br_scan_ctx *ctx,
                                 bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ArtifactoryReferenceToken scan arguments");
    const reference_patterns *compiled = detector->state;
    if (!compiled->token || !compiled->host)
        return fail(error, "uninitialized ArtifactoryReferenceToken patterns");
    br_captures tokens = {0}, found = {0};
    br_endpoint_list endpoints = {0}, hosts = {0};
    int rc = br_captures_find(compiled->token, input, &tokens, true, error);
    if (!rc) rc = br_captures_find(compiled->host, input, &found, false, error);
    if (!rc) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL,
                                        detector->cloud_endpoint, &found, &endpoints, error);
    for (size_t i = 0; !rc && i < endpoints.len; ++i) {
        const char *host = endpoints.items[i];
        if (!strncmp(host, "https://", 8)) host += 8;
        rc = br_endpoint_list_push(&hosts, host, true, error);
    }
    /* Both upstream maps are unique; their Cartesian-product order is unspecified. */
    for (size_t t = 0; !rc && t < tokens.len; ++t) {
        for (size_t h = 0; !rc && h < hosts.len; ++h) {
            bool cached = false;
            if (br_host_cache_contains(&invalid_hosts, hosts.items[h], &cached) != 0) {
                rc = fail(error, "could not read ArtifactoryReferenceToken host cache");
                break;
            }
            /* Keep cached hosts in this local list: they may expire before another token. */
            if (cached) continue;
            br_result result = {0};
            bool no_host = false;
            if (br_finding_pair(&result, detector->type, tokens.items[t], "token",
                                 hosts.items[h], "domain") != 0 ||
                (verify && verify_reference_token(ctx, hosts.items[h], tokens.items[t],
                                                  &result, &no_host) != 0)) {
                rc = fail(error, "out of memory creating ArtifactoryReferenceToken result");
            } else if (no_host) {
                if (br_host_cache_add(&invalid_hosts, hosts.items[h]) != 0)
                    rc = fail(error, "could not cache ArtifactoryReferenceToken host");
            } else if (br_results_push(out, &result) != 0) {
                rc = fail(error, "out of memory appending ArtifactoryReferenceToken result");
            }
            br_result_clear(&result);
        }
    }
    br_captures_clear(&tokens);
    br_captures_clear(&found);
    br_endpoint_list_clear(&endpoints);
    br_endpoint_list_clear(&hosts);
    return rc;
}

static reference_patterns patterns;
static const char *const keywords[] = {"cmVmdGtu"};
static const br_detector reference_token = {
    .type = 1042, .version = 0, .name = "ArtifactoryReferenceToken", .custom_name = "",
    .description = "JFrog Artifactory is a binary repository manager. Reference tokens are "
                   "64-character access tokens that can be used to authenticate API requests, "
                   "providing access to repositories, builds, and artifacts.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_reference_token,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};

int br_artifactoryreferencetoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ArtifactoryReferenceToken detector output");
    *out = NULL;
    if (!patterns.token &&
        br_regex_compile("\\b(cmVmdGtu[A-Za-z0-9]{56})\\b", &patterns.token, error) != 0)
        return -1;
    if (!patterns.host &&
        br_regex_compile("\\b([A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9]\\.jfrog\\.io)",
                         &patterns.host, error) != 0)
        return -1;
    *out = &reference_token;
    return 0;
}
