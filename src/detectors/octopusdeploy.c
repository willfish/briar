/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/octopusdeploy/octopusdeploy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *url; } octopusdeploy_patterns;

static int octopusdeploy_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int octopusdeploy_finding(br_result *result, br_slice domain, br_slice token)
{
    /* Regex bounds the token to API- plus 29-34 word bytes, so [:8] is in range. */
    if (token.len < 8 || token.len > 38) return -1;
    if (br_finding_key_bytes(result, 1056, token, "key") != 0) return -1;
    if (!domain.data || domain.len > INT_MAX || domain.len > SIZE_MAX - token.len - 1) return -1;
    /* Pair helper is key-first. Source RawV2 is DOMAIN:TOKEN. */
    result->raw_v2.len = domain.len + 1 + token.len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    result->redacted = malloc(12);
    if (!result->raw_v2.data || !result->redacted) return -1;
    memcpy(result->raw_v2.data, domain.data, domain.len);
    result->raw_v2.data[domain.len] = ':';
    memcpy(result->raw_v2.data + domain.len + 1, token.data, token.len);
    memcpy(result->redacted, token.data, 8);
    memcpy(result->redacted + 8, "...", 4);
    br_json *part = json_object_new_string_len((const char *)domain.data, (int)domain.len);
    if (!part) return -1;
    if (json_object_object_add(result->secret_parts, "url", part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int octopusdeploy_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : octopusdeploy_fail(error, "cannot create OctopusDeploy verification cause");
}

/* 0 keeps the candidate. -1 is fatal for this invocation. */
static int octopusdeploy_verify(const br_scan_ctx *ctx, br_slice domain, const char *token,
                                br_slice credential, bool *verified, char **cause, char **error)
{
    static const char suffix[] = "/api/users/me";
    *verified = false;
    *cause = NULL;
    if (domain.len > SIZE_MAX - 8 - (sizeof(suffix) - 1))
        return octopusdeploy_fail(error, "OctopusDeploy URL too large");
    char *url = malloc(8 + domain.len + sizeof(suffix));
    if (!url) return octopusdeploy_fail(error, "cannot create OctopusDeploy URL");
    /* url.URL.String leaves this lower-ASCII host and literal path unchanged.
     * Complete that transform before the nil-context constructor failure. */
    memcpy(url, "https://", 8);
    memcpy(url + 8, domain.data, domain.len);
    memcpy(url + 8 + domain.len, suffix, sizeof(suffix));
    int rc = 0;
    if (!ctx) {
        rc = octopusdeploy_cause(cause, "net/http: nil Context", error);
        free(url);
        return rc;
    }
    /* Header.Set canonicalizes the source X-Octopus-ApiKey spelling. */
    const br_header header = {"X-Octopus-Apikey", token};
    if (credential.len > SIZE_MAX - 5) {
        free(url);
        return octopusdeploy_fail(error, "OctopusDeploy dedup key too large");
    }
    unsigned char *key = malloc(5 + credential.len);
    if (!key) {
        free(url);
        return octopusdeploy_fail(error, "cannot create OctopusDeploy dedup key");
    }
    memcpy(key, "1056:", 5);
    memcpy(key + 5, credential.data, credential.len);
    const br_http_request request = {
        .method = "GET", .url = url, .headers = &header, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 1056,
        .dedup_key = {key, 5 + credential.len},
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool good = false;
    /* Default client is a distinct PUBLIC dedup clone. Owned clients promote a
     * present body_error to a Do error before status. Do not strip the key. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* A failed send is an error even when the diagnostic is NULL. Do not
         * invent fallback text; the scan setter still runs with that NULL. */
        if (transport_error) rc = octopusdeploy_cause(cause, transport_error, error);
    } else if (response.status == 200 || response.status == 403) good = true;
    else if (response.status != 401) {
        char message[80];
        int len = snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        if (len < 0 || (size_t)len >= sizeof(message))
            rc = octopusdeploy_fail(error, "cannot format OctopusDeploy status cause");
        else rc = octopusdeploy_cause(cause, message, error);
    }
    br_http_release(ctx, &response);
    free(transport_error);
    free(key);
    free(url);
    if (rc == 0) *verified = good;
    return rc == 0 ? 0 : -1;
}

static int octopusdeploy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return octopusdeploy_fail(error, "invalid or uninitialized OctopusDeploy scan");
    const octopusdeploy_patterns *patterns = detector->state;
    if (!patterns->url || !patterns->token)
        return octopusdeploy_fail(error, "uninitialized OctopusDeploy patterns");
    size_t original_len = out->len;
    br_captures urls = {0}, tokens = {0};
    char *owned_error = NULL;
    /* Both unique scans run even if the other set is empty. Source map order is
     * unspecified; first-seen URL then first-seen token is one allowed order. */
    int rc = br_captures_find(patterns->url, input, &urls, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    for (size_t u = 0; rc == 0 && u < urls.len; ++u) {
        for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
            br_slice domain = br_captures_at(&urls, u), token = br_captures_at(&tokens, t);
            br_result result = {0};
            if (octopusdeploy_finding(&result, domain, token) != 0)
                rc = octopusdeploy_fail(&owned_error, "cannot create OctopusDeploy result");
            if (rc == 0 && verify) {
                bool verified = false;
                char *cause = NULL;
                rc = octopusdeploy_verify(ctx, domain, tokens.items[t],
                    (br_slice){result.raw_v2.data, result.raw_v2.len}, &verified, &cause, &owned_error);
                if (rc == 0 && br_result_set_verification_error(&result, cause, &token, 1) != 0)
                    rc = octopusdeploy_fail(&owned_error, "cannot set OctopusDeploy verification error");
                /* Source assigns Verified only after the token-only setter. */
                if (rc == 0) result.verified = verified;
                free(cause);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = octopusdeploy_fail(&owned_error, "cannot append OctopusDeploy result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&urls);
    br_captures_clear(&tokens);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static octopusdeploy_patterns octopusdeploy_compiled;
static const char *const octopusdeploy_keywords[] = {"octopus"};
static const br_detector octopusdeploy_detector = {
    .type = 1056, .version = 0, .name = "OctopusDeploy", .custom_name = "",
    .description = "Octopus Deploy is a DevOps deployment automation platform. Octopus Deploy API keys can be used to automate deployments, manage projects, environments, and infrastructure resources.",
    .keywords = octopusdeploy_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &octopusdeploy_compiled, .scan = octopusdeploy_scan,
};

int br_octopusdeploy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return octopusdeploy_fail(error, "invalid OctopusDeploy detector output");
    *out = NULL;
    if (!octopusdeploy_compiled.token) {
        br_regex *token = NULL, *url = NULL;
        int rc = br_regex_compile("\\b(API-[A-Z0-9]{29,34})\\b", &token, error);
        if (rc == 0) rc = br_regex_compile("\\b([a-z0-9-]+\\.octopus\\.app)\\b", &url, error);
        if (rc != 0) {
            br_regex_free(token);
            br_regex_free(url);
            return -1;
        }
        octopusdeploy_compiled = (octopusdeploy_patterns){token, url};
    }
    *out = &octopusdeploy_detector;
    return 0;
}
