/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/artifactory/artifactory.go. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "host_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *url; } artifactory_patterns;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_artifactory(const br_scan_ctx *ctx, const char *token,
                              const char *host, br_result *result, bool *no_host)
{
    const char suffix[] = "/artifactory/api/system/ping";
    size_t host_len = strlen(host), overhead = sizeof("https://") - 1 + sizeof(suffix);
    if (host_len > SIZE_MAX - overhead) return -1;
    char *url = malloc(host_len + overhead);
    if (!url) return -1;
    snprintf(url, host_len + overhead, "https://%s%s", host, suffix);
    const br_header headers[] = {{"X-JFrog-Art-Api", token}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 181,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *no_host = true;
        else cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            /* ReadAll must succeed before searching even a matching partial body. */
            if (response.body_error) cause = response.body_error;
            else result->verified = br_slice_find(response.body,
                (br_slice){(const unsigned char *)"OK", 2}, 0) != SIZE_MAX;
            break;
        case 401:
        case 403:
        case 302: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(url);
    return rc;
}

static int scan_artifactory(const br_detector *detector, const br_scan_ctx *ctx,
                            bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ArtifactoryAccessToken scan arguments");
    const artifactory_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->url)
        return fail(error, "uninitialized ArtifactoryAccessToken patterns");
    br_captures keys = {0}, found = {0};
    br_endpoint_list endpoints = {0}, hosts = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->url, input, &found, false, error);
    if (!rc) rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "", &found, &endpoints, error);
    for (size_t i = 0; !rc && i < endpoints.len; ++i) {
        const char *host = endpoints.items[i];
        if (!strncmp(host, "https://", 8)) host += 8;
        rc = br_endpoint_list_push(&hosts, host, true, error);
    }
    bool *removed = !rc && keys.len && hosts.len ? calloc(hosts.len, sizeof(*removed)) : NULL;
    if (!rc && keys.len && hosts.len && !removed)
        rc = fail(error, "out of memory tracking Artifactory hosts");
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t h = 0; !rc && h < hosts.len; ++h) {
            if (removed[h]) continue;
            bool cached = false;
            if (br_host_cache_contains(&invalid_hosts, hosts.items[h], &cached) != 0) {
                rc = fail(error, "wall clock unavailable");
                break;
            }
            if (cached) { removed[h] = true; continue; } /* Source deletes from this scan's URL map. */
            br_result result = {0};
            bool no_host = false;
            if (br_finding_pair(&result, detector->type, keys.items[k], "token", hosts.items[h], "domain") != 0 ||
                (verify && verify_artifactory(ctx, keys.items[k], hosts.items[h], &result, &no_host) != 0)) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating ArtifactoryAccessToken result");
                break;
            }
            if (no_host) {
                br_result_clear(&result);
                if (br_host_cache_add(&invalid_hosts, hosts.items[h]) != 0)
                    rc = fail(error, "cannot store invalid Artifactory host");
                continue;
            }
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending ArtifactoryAccessToken result");
            }
        }
    }
    free(removed);
    br_endpoint_list_clear(&hosts);
    br_endpoint_list_clear(&endpoints);
    br_captures_clear(&found);
    br_captures_clear(&keys);
    return rc;
}

static artifactory_patterns patterns;
static const char *const keywords[] = {"artifactory", "jfrog.io", "AKCp"};
static const br_detector artifactory = {
    .type = 181, .version = 0, .name = "ArtifactoryAccessToken", .custom_name = "",
    .description = "Artifactory is a repository manager that supports all major package formats. "
                   "Artifactory access tokens can be used to authenticate and perform operations on repositories.",
    .keywords = keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_artifactory,
    .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};

int br_artifactory_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ArtifactoryAccessToken detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile("\\b(AKCp[a-zA-Z0-9]{69})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.url && br_regex_compile(
            "\\b([A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9]\\.jfrog\\.io)", &patterns.url, error) != 0)
        return -1;
    *out = &artifactory;
    return 0;
}
