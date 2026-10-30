/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/storyblokpersonalaccesstoken. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char storyblok_url[] = "https://mapi.storyblok.com/v1/spaces/";

static int storyblok_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int storyblok_set(br_result *result, const char *cause, char **error)
{
    /* Source passes no secrets. A cause containing the token stays visible. */
    return br_result_set_verification_error(result, cause, NULL, 0)
        ? storyblok_fail(error, "cannot set StoryblokPersonalAccessToken verification error") : 0;
}

static int storyblok_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (token.len != 52) return storyblok_fail(error, "invalid StoryblokPersonalAccessToken capture");
    if (!ctx) return storyblok_set(result, "net/http: nil Context", error);
    char authorization[53];
    memcpy(authorization, token.data, 52);
    authorization[52] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = storyblok_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = storyblok_fail(error, "cannot format StoryblokPersonalAccessToken status");
        else cause = status_error;
    }
    /* Drain and close errors are ignored. The raw token is the Authorization value. */
    if (!rc) rc = storyblok_set(result, cause, error);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int storyblok_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return storyblok_fail(error, "invalid or uninitialized StoryblokPersonalAccessToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = storyblok_fail(&owned_error, "cannot create StoryblokPersonalAccessToken result");
        else if (verify && storyblok_verify(ctx, token, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = storyblok_fail(&owned_error, "cannot append StoryblokPersonalAccessToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const storyblok_keywords[] = {"storyblok"};
static br_detector storyblok_detector = {
    .type = 1016, .version = 0, .name = "StoryblokPersonalAccessToken", .custom_name = "",
    .description = "Storyblok is a headless CMS that allows developers to build flexible and powerful content management solutions.\n\t\t\tStoryblok personal access tokens can be used with management APIs.\n\t\t\tThe Storyblok Management API allows you to create, edit, update, and delete content using a common interface",
    .keywords = storyblok_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = storyblok_scan,
};

int br_storyblokpersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return storyblok_fail(error, "invalid StoryblokPersonalAccessToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&storyblok_detector,
            "\\b([0-9A-Za-z]{22}tt-[0-9]{6}-[A-Za-z0-9_-]{20})\\b", error) != 0)
        return -1;
    *out = &storyblok_detector;
    return 0;
}
