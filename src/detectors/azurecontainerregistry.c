/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azurecontainerregistry. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *username, *password; } registry_patterns;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int registry_result(br_result *result, int32_t type, const char *username, const char *password)
{
    if (br_finding_key(result, type, password, "password") != 0) return -1;
    br_json *name = json_object_new_string(username);
    if (!name) return -1;
    if (json_object_object_add(result->secret_parts, "username", name) != 0) {
        json_object_put(name);
        return -1;
    }
    result->redacted = strdup(username);
    if (!result->redacted) return -1;
    char raw_v2[208];
    int n = snprintf(raw_v2, sizeof(raw_v2), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    if (n < 0 || (size_t)n >= sizeof(raw_v2)) return -1;
    result->raw_v2.data = malloc((size_t)n);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, raw_v2, (size_t)n);
    result->raw_v2.len = (size_t)n;
    return 0;
}

static int verify_registry(const br_scan_ctx *ctx, const char *username, const char *password,
                            br_result *result, bool *no_host)
{
    *no_host = false;
    char url[160];
    int n = snprintf(url, sizeof(url), "https://%s.azurecr.io/v2/", username);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    char *authorization = NULL, *error = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)username, strlen(username)},
                           (br_slice){(const unsigned char *)password, strlen(password)},
                           &authorization, &error) != 0) {
        free(error);
        free(authorization);
        return -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 958,
    };
    br_http_response response = {0};
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *no_host = true;
        else cause = error ? error : "HTTP transport failed";
    } else {
        /* No Docker challenge flow: source checks only this Basic-auth GET. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(authorization);
    return rc;
}

static int scan_registry(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureContainerRegistry scan arguments");
    const registry_patterns *compiled = detector->state;
    if (!compiled->username || !compiled->password)
        return fail(error, "uninitialized AzureContainerRegistry patterns");
    br_captures usernames = {0}, passwords = {0};
    int rc = br_captures_find(compiled->username, input, &usernames, true, error);
    if (!rc) rc = br_captures_find(compiled->password, input, &passwords, true, error);
    bool *available = NULL;
    if (!rc && passwords.len) {
        available = calloc(passwords.len, sizeof(*available));
        if (!available) rc = fail(error, "out of memory collecting AzureContainerRegistry passwords");
        else {
            for (size_t k = 0; k < passwords.len; ++k)
                available[k] = br_ascii_shannon_entropy(br_captures_at(&passwords, k)) >= 4.0;
        }
    }
    /* Maps are unique and unordered upstream. Keep one valid first-seen order,
     * with a mutable remaining-password set shared across all usernames. */
    for (size_t u = 0; !rc && u < usernames.len; ++u) {
        const char *username = usernames.items[u];
        if (!strcmp(username, "privatelink") || !strcmp(username, "myacr")) continue;
        for (size_t k = 0; !rc && k < passwords.len; ++k) {
            if (!available[k]) continue;
            if (verify) {
                bool cached = false;
                if (br_host_cache_contains(&invalid_hosts, username, &cached) != 0) {
                    rc = fail(error, "could not read AzureContainerRegistry host cache");
                    break;
                }
                if (cached) break; /* Source continues the outer endpoint loop. */
            }
            br_result result = {0};
            bool no_host = false;
            if (registry_result(&result, detector->type, username, passwords.items[k]) != 0 ||
                (verify && verify_registry(ctx, username, passwords.items[k], &result, &no_host) != 0)) {
                rc = fail(error, "could not create AzureContainerRegistry result");
            }
            if (!rc && no_host) {
                /* Username, not the full hostname. Suppress this candidate and
                 * every remaining password for this username, not earlier results. */
                if (br_host_cache_add(&invalid_hosts, username) != 0)
                    rc = fail(error, "could not cache AzureContainerRegistry username");
                br_result_clear(&result);
                break;
            }
            bool verified = result.verified;
            if (!rc && verified) available[k] = false; /* Delete globally before append. */
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending AzureContainerRegistry result");
            br_result_clear(&result);
            if (verified) break;
        }
    }
    free(available);
    br_captures_clear(&usernames);
    br_captures_clear(&passwords);
    return rc;
}

static bool registry_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static registry_patterns patterns;
static const char *const keywords[] = {".azurecr.io"};
static const br_detector registry = {
    .type = 958, .version = 0, .name = "AzureContainerRegistry", .custom_name = "",
    .description = "Azure's container registry is used to store docker containers. An API key "
                   "can be used to override existing containers, read sensitive data, and do "
                   "other operations inside the container registry.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_registry, .false_positive = registry_false_positive,
};

int br_azurecontainerregistry_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureContainerRegistry detector output");
    *out = NULL;
    if (!patterns.username && br_regex_compile("([a-z0-9][a-z0-9-]{1,100}[a-z0-9])\\.azurecr\\.io",
                                                &patterns.username, error) != 0) return -1;
    /* The capture wrapper preserves the source's whole-password match. */
    if (!patterns.password && br_regex_compile("\\b([a-zA-Z0-9+/]{42}\\+ACR[a-zA-Z0-9]{6})\\b",
                                                &patterns.password, error) != 0) return -1;
    *out = &registry;
    return 0;
}
