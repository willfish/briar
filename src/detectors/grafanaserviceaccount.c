/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/grafanaserviceaccount/grafanaserviceaccount.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } grafanaserviceaccount_patterns;

static int grafanaserviceaccount_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int grafanaserviceaccount_verify(const br_scan_ctx *ctx, br_slice key,
                                        br_slice domain, br_result *result,
                                        bool *keep, char **error)
{
    static const char prefix[] = "https://";
    static const char suffix[] = "/api/access-control/user/permissions";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (domain.len > SIZE_MAX - fixed)
        return grafanaserviceaccount_fail(error, "GrafanaServiceAccount URL size overflow");
    char *url = malloc(fixed + domain.len);
    if (!url) return grafanaserviceaccount_fail(error, "cannot allocate GrafanaServiceAccount URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain.data, domain.len);
    memcpy(url + sizeof(prefix) - 1 + domain.len, suffix, sizeof(suffix));
    /* The complete URL is constructed before the source nil-context skip. */
    if (!ctx) { *keep = false; free(url); return 0; }
    char authorization[sizeof("Bearer ") + 46];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 46);
    authorization[53] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* Retain the whole shared setup/Do error domain, without text classification.
     * All statuses ignore body bytes and read errors. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0) cause = send_error;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = grafanaserviceaccount_fail(error, "cannot format GrafanaServiceAccount status");
        else cause = status_error;
    }
    if (rc == 0 && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = grafanaserviceaccount_fail(error, "cannot set GrafanaServiceAccount verification error");
    /* Keep provider-original URL/auth/captures alive through every release.
     * Ordinary ABI1 effective headers and synthesized UA end at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc;
}

static int grafanaserviceaccount_scan(const br_detector *detector, const br_scan_ctx *ctx,
                                      bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return grafanaserviceaccount_fail(error, "invalid GrafanaServiceAccount scan");
    const grafanaserviceaccount_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, false, &owned_error);
    /* TrimSpace is a no-op for both grammars. Preserve every key-major
     * occurrence product; the engine's 1024 span hint is not a local cap. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
            br_slice domain = br_captures_at(&domains, d);
            br_result result = {0};
            bool keep = true;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", domain, "domain",
                                      (br_slice){(const unsigned char *)":", 1}) != 0)
                rc = grafanaserviceaccount_fail(&owned_error, "cannot create GrafanaServiceAccount result");
            if (rc == 0) {
                /* Raw remains KEY; only RawV2 has the reversed DOMAIN:KEY layout. */
                memcpy(result.raw_v2.data, domain.data, domain.len);
                result.raw_v2.data[domain.len] = ':';
                memcpy(result.raw_v2.data + domain.len + 1, key.data, key.len);
            }
            if (rc == 0 && verify)
                rc = grafanaserviceaccount_verify(ctx, key, domain, &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = grafanaserviceaccount_fail(&owned_error, "cannot append GrafanaServiceAccount result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static grafanaserviceaccount_patterns grafanaserviceaccount_compiled;
static const char *const grafanaserviceaccount_keywords[] = {"glsa_"};
static const br_detector grafanaserviceaccount_detector = {
    .type = 963, .version = 0, .name = "GrafanaServiceAccount", .custom_name = "",
    .description = "Grafana service accounts are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings.",
    .keywords = grafanaserviceaccount_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &grafanaserviceaccount_compiled, .scan = grafanaserviceaccount_scan,
};

int br_grafanaserviceaccount_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return grafanaserviceaccount_fail(error, "invalid GrafanaServiceAccount detector output");
    *out = NULL;
    if (!grafanaserviceaccount_compiled.key &&
        br_regex_compile("\\b(glsa_[0-9a-zA-Z_]{41})\\b", &grafanaserviceaccount_compiled.key, error) != 0) return -1;
    if (!grafanaserviceaccount_compiled.domain &&
        br_regex_compile("\\b([a-zA-Z0-9-]+\\.grafana\\.net)\\b", &grafanaserviceaccount_compiled.domain, error) != 0) return -1;
    *out = &grafanaserviceaccount_detector;
    return 0;
}
