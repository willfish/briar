/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/storyblok/storyblok.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { STORY_ABORT = -1, STORY_KEEP = 0 } story_outcome;

static int story_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int story_cause(br_result *result, const char *cause, char **error)
{
    /* SetVerificationError is called with no secrets, so the token is not redacted. */
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return story_fail(error, "cannot set Storyblok verification error");
    return 0;
}

static story_outcome story_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char url[sizeof("https://api.storyblok.com/v1/cdn/spaces/me/?token=") + 24];
    int n = snprintf(url, sizeof(url), "https://api.storyblok.com/v1/cdn/spaces/me/?token=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        story_fail(error, "cannot format Storyblok URL");
        return STORY_ABORT;
    }
    if (!ctx) {
        if (story_cause(result, "net/http: nil Context", error) != 0) return STORY_ABORT;
        return STORY_KEEP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    /* Body is discarded. 200 verifies, 401 is determinate, every other status
     * is an unexpected-status error. Do errors use the transport text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int written = snprintf(status_error, sizeof(status_error),
                               "unexpected status code: %d", response.status);
        if (written < 0 || (size_t)written >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            story_fail(error, "cannot format Storyblok status");
            return STORY_ABORT;
        }
        cause = status_error;
    }
    int rc = story_cause(result, cause, error);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? STORY_KEEP : STORY_ABORT;
}

static int story_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return story_fail(error, "invalid or uninitialized Storyblok scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Go collects a map, so duplicates collapse. First-seen order is stable;
     * map iteration order is unspecified upstream. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        story_outcome outcome = STORY_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            story_fail(&owned_error, "cannot create Storyblok result");
            outcome = STORY_ABORT;
        } else if (verify)
            outcome = story_verify(ctx, key, &result, &owned_error);
        if (outcome == STORY_ABORT) rc = -1;
        else if (br_results_push(out, &result) != 0) {
            story_fail(&owned_error, "cannot append Storyblok result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const story_keywords[] = {"storyblok"};
static br_detector story_detector = {
    .type = 222, .version = 0, .name = "StoryblokAccessToken", .custom_name = "",
    .description = "Storyblok is a headless CMS that allows developers to build flexible and powerful "
                   "content management solutions. Storyblok tokens can be used to access and modify "
                   "content within a Storyblok space.",
    .keywords = story_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = story_scan,
};

int br_storyblok_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return story_fail(error, "invalid Storyblok detector output");
    *out = NULL;
    if (br_key_pattern_init(&story_detector, "\\b([0-9A-Za-z]{22}tt)\\b", error) != 0) return -1;
    *out = &story_detector;
    return 0;
}
