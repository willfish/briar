/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/heroku/{v1,v2}/heroku.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int heroku_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Both source versions call v1's helper with their own ordinary SANE client.
 * There is no keyed transport or shared coalescing namespace to introduce. */
static int heroku_verify(const br_scan_ctx *ctx, br_slice key, bool *verified,
                          char **cause, char **error)
{
    *verified = false;
    *cause = NULL;
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        return *cause ? 0 : heroku_fail(error, "cannot create Heroku constructor cause");
    }
    /* NewRequestWithContext precedes header assembly. The two grammars bound
     * Bearer storage to 44 bytes for v1 and 73 for v2, including the NUL. */
    size_t auth_size = sizeof("Bearer ") + key.len;
    char *authorization = malloc(auth_size);
    if (!authorization) return heroku_fail(error, "cannot allocate Heroku authorization");
    int n = snprintf(authorization, auth_size, "Bearer %.*s", (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n != auth_size - 1) {
        free(authorization);
        return heroku_fail(error, "cannot format Heroku authorization");
    }
    const br_header headers[] = {
        {"Accept", "application/vnd.heroku+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.heroku.com/account",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = 19,
    };
    br_http_response response = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, cause) != 0) {
        /* Retain the entire shared setup/Do domain, without unwrapping or
         * classifying diagnostics. Our own fallback allocation is checked. */
        if (!*cause) {
            *cause = strdup("HTTP transport failed");
            if (!*cause) rc = heroku_fail(error, "cannot create Heroku transport cause");
        }
    } else if (response.status == 200) {
        *verified = true;
    } else if (response.status != 401) {
        int needed = snprintf(NULL, 0, "unexpected status code: %d", response.status);
        if (needed < 0) rc = heroku_fail(error, "cannot format Heroku status cause");
        else {
            *cause = malloc((size_t)needed + 1);
            if (!*cause) rc = heroku_fail(error, "cannot allocate Heroku status cause");
            else if (snprintf(*cause, (size_t)needed + 1, "unexpected status code: %d", response.status) != needed)
                rc = heroku_fail(error, "cannot format Heroku status cause");
        }
    }
    /* Ignore body/read errors at every status. Source drains and closes before
     * returning to its caller. ABI1 eagerly releases once even on setup failure;
     * original auth/captures survive release, synthesized headers/UA do not. */
    br_http_release(ctx, &response);
    free(authorization);
    return rc;
}

static int heroku_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return heroku_fail(error, "invalid or uninitialized Heroku scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace cannot change either ASCII grammar. Keep every original
         * occurrence, including duplicates, without semantic/entropy filtering. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = heroku_fail(&owned_error, "cannot create Heroku finding");
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            rc = heroku_verify(ctx, key, &verified, &cause, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                /* Source supplies no secrets: keep the whole cause unchanged.
                 * NULL is still passed to the checked, no-op-not-clear setter. */
                if (br_result_set_verification_error(&result, cause, NULL, 0) != 0)
                    rc = heroku_fail(&owned_error, "cannot set Heroku verification error");
            }
            free(cause);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = heroku_fail(&owned_error, "cannot append Heroku finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const heroku_v1_keywords[] = {"heroku"};
static br_detector heroku_v1 = {
    .type = 19, .version = 1, .name = "Heroku", .custom_name = "",
    .description = "Heroku is a cloud platform that lets companies build, deliver, monitor and scale apps. Heroku API keys can be used to access and manage Heroku applications and services.",
    .keywords = heroku_v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = heroku_scan,
};
static const char *const heroku_v2_keywords[] = {"HRKU-AA"};
static br_detector heroku_v2 = {
    .type = 19, .version = 2, .name = "Heroku", .custom_name = "",
    .description = "Heroku is a cloud platform that lets companies build, deliver, monitor and scale apps. Heroku API keys can be used to access and manage Heroku applications and services.",
    .keywords = heroku_v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = heroku_scan,
};

int br_heroku_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return heroku_fail(error, "invalid Heroku v1 detector output");
    *out = NULL;
    if (!heroku_v1.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(heroku_v1_keywords, 1,
                "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                &regex, error) != 0) return -1;
        heroku_v1.state = regex;
    }
    *out = &heroku_v1;
    return 0;
}

int br_heroku_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return heroku_fail(error, "invalid Heroku v2 detector output");
    *out = NULL;
    if (!heroku_v2.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(HRKU-AA[0-9a-zA-Z_-]{58})\\b", &regex, error) != 0) return -1;
        heroku_v2.state = regex;
    }
    *out = &heroku_v2;
    return 0;
}
