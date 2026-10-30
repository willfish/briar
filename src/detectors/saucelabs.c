/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/saucelabs/saucelabs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char fixed_base_url[] = "api.us-west-1.saucelabs.com";

typedef struct { br_regex *username, *key, *base_url; } saucelabs_patterns;

static int saucelabs_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int saucelabs_result(br_result *result, int32_t type, const char *username,
                            const char *key, const char *base_url)
{
    size_t user_len = strlen(username), key_len = strlen(key);
    if (br_finding_key(result, type, username, "username") != 0) return -1;
    br_json *secret = json_object_new_string(key);
    if (!secret || json_object_object_add(result->secret_parts, "key", secret) != 0) {
        json_object_put(secret);
        return -1;
    }
    result->raw_v2.data = malloc(user_len + key_len);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, username, user_len);
    memcpy(result->raw_v2.data + user_len, key, key_len);
    result->raw_v2.len = user_len + key_len;
    br_json *extra = json_object_new_object();
    br_json *url = json_object_new_string(base_url);
    if (!extra || !url || json_object_object_add(extra, "Base URL", url) != 0) {
        json_object_put(url);
        json_object_put(extra);
        return -1;
    }
    result->extra_data = extra;
    return 0;
}

static int saucelabs_verify(const br_scan_ctx *ctx, const char *username, const char *key,
                            const char *base_url, br_result *result, char **error)
{
    char url[160];
    int n = snprintf(url, sizeof(url), "https://%s/team-management/v1/teams", base_url);
    if (n < 0 || (size_t)n >= sizeof(url))
        return saucelabs_fail(error, "cannot create SauceLabs URL");
    const char *cause = NULL;
    char status_error[64];
    bool verified = false;
    char *authorization = NULL, *transport_error = NULL;
    br_http_response response = {0};
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    /* URL is complete before the constructor. A nil context is that error. */
    if (!ctx) cause = "net/http: nil Context";
    else if (br_http_basic_auth((br_slice){(const unsigned char *)username, strlen(username)},
                                secret, &authorization, error) != 0)
        return saucelabs_fail(error, "cannot create SauceLabs basic authorization");
    else {
        const br_header header = {"Authorization", authorization};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = &header, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status == 200 || response.status == 403) verified = true;
        else if (response.status != 401) {
            int wrote = snprintf(status_error, sizeof(status_error),
                                 "unexpected status code %d", response.status);
            if (wrote < 0 || (size_t)wrote >= sizeof(status_error)) {
                br_http_release(ctx, &response);
                free(transport_error);
                free(authorization);
                return saucelabs_fail(error, "cannot format SauceLabs status cause");
            }
            cause = status_error;
        }
    }
    /* Setter redacts the key, not the username. Drain errors are ignored. */
    int set = br_result_set_verification_error(result, cause, &secret, 1);
    if (ctx) br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (set != 0) return saucelabs_fail(error, "cannot set SauceLabs verification error");
    result->verified = verified;
    return 0;
}

static int saucelabs_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return saucelabs_fail(error, "invalid or uninitialized SauceLabs scan");
    const saucelabs_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures users = {0}, keys = {0}, urls = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->username, input, &users, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->base_url, input, &urls, true, &owned_error);
    if (rc == 0 && !urls.len && br_captures_push(&urls, (br_slice){(const unsigned char *)fixed_base_url,
                                                                   sizeof(fixed_base_url) - 1},
                                                 true, &owned_error) != 0)
        rc = -1;
    /* Source maps are unordered. First-seen username, key, then base URL is one
     * valid iteration. A captured host replaces the fixed fallback entirely. */
    for (size_t u = 0; rc == 0 && u < users.len; ++u) {
        for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
            for (size_t b = 0; rc == 0 && b < urls.len; ++b) {
                br_result result = {0};
                if (saucelabs_result(&result, detector->type, users.items[u], keys.items[k],
                                     urls.items[b]) != 0 ||
                    (verify && saucelabs_verify(ctx, users.items[u], keys.items[k], urls.items[b],
                                                &result, &owned_error) != 0))
                    rc = saucelabs_fail(&owned_error, "cannot create SauceLabs result");
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = saucelabs_fail(&owned_error, "cannot append SauceLabs result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&users);
    br_captures_clear(&keys);
    br_captures_clear(&urls);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const saucelabs_keywords[] = {"saucelabs"};
static const char *const saucelabs_user_keywords[] = {"saucelabs", "username"};
static saucelabs_patterns saucelabs_state;
static br_detector saucelabs_detector = {
    .type = 398, .version = 0, .name = "SauceLabs", .custom_name = "",
    .description = "A service for cross browser testing, API keys can create and access tests from potentially sensitive internal websites",
    .keywords = saucelabs_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &saucelabs_state, .scan = saucelabs_scan,
};

int br_saucelabs_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return saucelabs_fail(error, "invalid SauceLabs detector output");
    *out = NULL;
    if (!saucelabs_state.username &&
        br_regex_compile_prefixed(saucelabs_user_keywords, 2, "\\b([a-zA-Z0-9_\\.-]{2,70})",
                                  &saucelabs_state.username, error) != 0)
        return -1;
    if (!saucelabs_state.key &&
        br_regex_compile_prefixed(saucelabs_keywords, 1,
                                  "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b",
                                  &saucelabs_state.key, error) != 0)
        return -1;
    if (!saucelabs_state.base_url &&
        br_regex_compile("\\b(api\\.(?:us|eu)-(?:west|east|central)-[0-9].saucelabs\\.com)\\b",
                         &saucelabs_state.base_url, error) != 0)
        return -1;
    *out = &saucelabs_detector;
    return 0;
}
