/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/redhatpyxis/redhatpyxis.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char redhatpyxis_url[] =
    "https://catalog.redhat.com/api/containers/v1/projects/certification/requests/images?page_size=1&page=0";

static int redhatpyxis_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int redhatpyxis_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (token.len != 32) return redhatpyxis_fail(error, "invalid RedHatPyxis capture");
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &token, 1)
            ? redhatpyxis_fail(error, "cannot set RedHatPyxis verification error") : 0;
    char value[33];
    memcpy(value, token.data, 32);
    value[32] = '\0';
    unsigned char dedup_key[5 + 32];
    memcpy(dedup_key, "1055:", 5);
    memcpy(dedup_key + 5, token.data, 32);
    const br_header headers[] = {{"X-Api-Key", value}}; /* Set canonicalizes X-API-KEY. */
    const br_http_request request = {
        .method = "GET", .url = redhatpyxis_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)},
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    /* DoWithDedup buffers the body before status inspection. An owned client
     * turns body_error into this send failure. Borrowed transports reject the
     * dedup key before either callback; that rejection is the same Do error. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = redhatpyxis_fail(error, "cannot format RedHatPyxis status");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = redhatpyxis_fail(error, "cannot set RedHatPyxis verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int redhatpyxis_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return redhatpyxis_fail(error, "invalid or uninitialized RedHatPyxis scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = redhatpyxis_fail(&owned_error, "cannot create RedHatPyxis result");
        else if (verify && redhatpyxis_verify(ctx, token, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = redhatpyxis_fail(&owned_error, "cannot append RedHatPyxis result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const redhatpyxis_keywords[] = {"redhat", "pyxis"};
static br_detector redhatpyxis_detector = {
    .type = 1055, .version = 0, .name = "RedHatPyxis", .custom_name = "",
    .description = "Red Hat Pyxis is a container certification and metadata management platform. Red Hat Pyxis API keys can be used to authenticate against the Red Hat Ecosystem Catalog APIs and access container certification resources and metadata.",
    .keywords = redhatpyxis_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = redhatpyxis_scan,
};

int br_redhatpyxis_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return redhatpyxis_fail(error, "invalid RedHatPyxis detector output");
    *out = NULL;
    if (br_key_pattern_init(&redhatpyxis_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &redhatpyxis_detector;
    return 0;
}
