/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zenserp/zenserp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zenserp_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool zenserp_contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > body.len) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int zenserp_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char prefix[] = "https://app.zenserp.com/api/v2/search?q=\"test\"&apikey=";
    _Static_assert(sizeof(prefix) - 1 + 36 == 90, "Zenserp URL is 90 bytes plus NUL");
    if (key.len != 36) return zenserp_fail(error, "invalid Zenserp capture");
    /* The quoted query and raw key are concatenated before the constructor.
     * SaneHttpClientTimeOut(5s) is the existing sane client, not a new profile. */
    char url[91];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 36);
    url[90] = '\0';
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1)
            ? zenserp_fail(error, "cannot set Zenserp verification error") : 0;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) {
        if (response.body_error) cause = response.body_error;
        else if (zenserp_contains(response.body, "query")) result->verified = true;
    } else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = zenserp_fail(error, "cannot format Zenserp status");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = zenserp_fail(error, "cannot set Zenserp verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int zenserp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return zenserp_fail(error, "invalid or uninitialized Zenserp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = zenserp_fail(&owned_error, "cannot create Zenserp result");
        else if (verify && zenserp_verify(ctx, key, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = zenserp_fail(&owned_error, "cannot append Zenserp result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const zenserp_keywords[] = {"zenserp"};
static br_detector zenserp_detector = {
    .type = 553, .version = 0, .name = "Zenserp", .custom_name = "",
    .description = "Zenserp is a service that provides SERP (Search Engine Results Page) API. Zenserp API keys can be used to access search engine data programmatically.",
    .keywords = zenserp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zenserp_scan,
};

int br_zenserp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zenserp_fail(error, "invalid Zenserp detector output");
    *out = NULL;
    if (br_key_pattern_init(&zenserp_detector, "\\b([0-9a-z-]{36})\\b", error) != 0) return -1;
    *out = &zenserp_detector;
    return 0;
}
