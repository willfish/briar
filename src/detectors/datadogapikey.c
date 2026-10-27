/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/datadogapikey/datadogapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } datadogapikey_patterns;

static int datadogapikey_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int datadogapikey_verify(const br_scan_ctx *ctx, br_slice key, const char *base,
                               br_result *result, char **error)
{
    static const char suffix[] = "/api/v1/validate";
    size_t base_len = strlen(base);
    if (base_len > SIZE_MAX - sizeof(suffix))
        return datadogapikey_fail(error, "DatadogApikey request URL too large");
    /* BASE is unbounded. Own exactly one complete concatenated URL, without
     * path normalization, through synchronous send AND release. */
    char *url = malloc(base_len + sizeof(suffix));
    if (!url) return datadogapikey_fail(error, "cannot allocate DatadogApikey request URL");
    memcpy(url, base, base_len);
    memcpy(url + base_len, suffix, sizeof(suffix));
    if (!ctx) {
        int rc = br_result_set_verification_error(result, "net/http: nil Context", &key, 1);
        free(url);
        return rc != 0 ? datadogapikey_fail(error, "cannot store DatadogApikey verification error") : 0;
    }
    /* Go Header.Add canonicalizes DD-API-KEY. Borrow the complete captured key. */
    const br_header header = {"Dd-Api-Key", (const char *)key.data};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = &header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    int rc = 0;
    /* Retain the whole shared setup/allocation/Do error domain as a finding
     * error; ABI1 cannot distinguish stages by their diagnostic text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: verified = true; break;
        case 403: break;
        case 429: cause = "too many requests"; break;
        default: {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = datadogapikey_fail(error, "cannot format DatadogApikey status error");
            else cause = status_error;
            break;
        }
        }
    }
    if (rc == 0 && verified) {
        br_json *endpoint = json_object_new_string(base);
        if (!endpoint) rc = datadogapikey_fail(error, "cannot create DatadogApikey endpoint part");
        else if (json_object_object_add(result->secret_parts, "endpoint", endpoint) != 0) {
            json_object_put(endpoint);
            rc = datadogapikey_fail(error, "cannot create DatadogApikey endpoint part");
        } else result->verified = true;
        /* Success never calls the setter: an earlier endpoint error survives. */
    } else if (rc == 0 && br_result_set_verification_error(result, cause, &key, 1) != 0) {
        rc = datadogapikey_fail(error, "cannot store DatadogApikey verification error");
    }
    /* Failed attempts call the API-key-only setter even for NULL causes, which
     * are sticky no-ops. Do so before release; ignore every body/read error.
     * Source verifier-defers drain/close. Full Go URL construction, native SANE,
     * http.NoBody identity, eager release and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(url);
    return rc == 0 ? 0 : -1;
}

static int datadogapikey_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return datadogapikey_fail(error, "invalid or uninitialized DatadogApikey scan");
    const datadogapikey_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->host)
        return datadogapikey_fail(error, "uninitialized DatadogApikey patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, found = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->host, input, &found, true, &owned_error);
    /* Source prepares unique found HTTPS endpoints before the key loop, even
     * with verification disabled or no keys. No DNS-label or length cap.
     * First-seen order is one permitted upstream map traversal. */
    for (size_t i = 0; rc == 0 && i < found.len; ++i) {
        static const char scheme[] = "https://";
        size_t len = found.lengths[i];
        if (len > SIZE_MAX - sizeof(scheme)) {
            rc = datadogapikey_fail(&owned_error, "DatadogApikey found URL too large");
            break;
        }
        char *url = malloc(len + sizeof(scheme));
        if (!url) {
            rc = datadogapikey_fail(&owned_error, "cannot prepare DatadogApikey found URL");
            break;
        }
        memcpy(url, scheme, sizeof(scheme) - 1);
        memcpy(url + sizeof(scheme) - 1, found.items[i], len + 1);
        free(found.items[i]);
        found.items[i] = url;
        found.lengths[i] += sizeof(scheme) - 1;
    }
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        br_endpoint_list endpoints = {0};
        /* TrimSpace is a no-op. Retain ordered key occurrences, not unique keys. */
        if (br_finding_key_bytes(&result, detector->type, key, "api_key") != 0)
            rc = datadogapikey_fail(&owned_error, "cannot create DatadogApikey result");
        if (rc == 0 && verify)
            rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, detector->cloud_endpoint,
                                      &found, &endpoints, &owned_error);
        for (size_t e = 0; rc == 0 && e < endpoints.len; ++e) {
            rc = datadogapikey_verify(ctx, key, endpoints.items[e], &result, &owned_error);
            if (rc == 0 && result.verified) break;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = datadogapikey_fail(&owned_error, "cannot append DatadogApikey result");
        br_endpoint_list_clear(&endpoints);
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static datadogapikey_patterns datadogapikey_compiled;
static const char *const datadogapikey_keywords[] = {"datadog", "ddog-gov"};
static const br_detector datadogapikey_detector = {
    .type = 1043, .version = 0, .name = "DatadogApikey", .custom_name = "",
    .description = "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog.",
    .keywords = datadogapikey_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &datadogapikey_compiled, .scan = datadogapikey_scan,
    .validate_endpoints = br_endpoints_validate_configured,
    .cloud_endpoint = "https://api.datadoghq.com",
};

int br_datadogapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return datadogapikey_fail(error, "invalid DatadogApikey detector output");
    *out = NULL;
    static const char *const prefixes[] = {"datadog", "dd"};
    if (!datadogapikey_compiled.key && br_regex_compile_prefixed(prefixes, 2,
            "\\b([a-zA-Z0-9-]{32})\\b", &datadogapikey_compiled.key, error) != 0) return -1;
    if (!datadogapikey_compiled.host && br_regex_compile(
            "\\b(api(?:\\.[a-z0-9-]+)?\\.(?:datadoghq|ddog-gov)\\.(com|eu))\\b",
            &datadogapikey_compiled.host, error) != 0) return -1;
    *out = &datadogapikey_detector;
    return 0;
}
