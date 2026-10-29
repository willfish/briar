/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/instabot/instabot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int instabot_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool instabot_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* NewRequestWithContext's nil-context error drops the constructed finding. */
    if (!ctx) return false;
    const br_header headers[] = {
        {"X-Instabot-Api-Key", (const char *)key.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.instabot.io/v1",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/Do error domain is false-kept, without a setter.
     * Source consumes neither body bytes nor body-read errors at any status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original capture/header values survive one ordinary release per attempt,
     * including failed setup. Synthesized request/headers/UA end at send return;
     * this eager release does not reproduce source scan-deferred Close timing. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int instabot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return instabot_fail(error, "invalid or uninitialized Instabot scan");
    const br_regex *pattern = *(br_regex *const *)detector->state;
    if (!pattern) return instabot_fail(error, "uninitialized Instabot pattern");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(pattern, input, &keys, false, &owned_error);
    /* TrimSpace is a no-op for this alphabet. Preserve original occurrences,
     * duplicates and 44-byte prefixes; there is no Base64 validation/decoding. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 44)
            rc = instabot_fail(&owned_error, "invalid Instabot capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = instabot_fail(&owned_error, "cannot create Instabot result");
        if (rc == 0 && verify) keep = instabot_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = instabot_fail(&owned_error, "cannot append Instabot result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_regex *instabot_pattern;
static const char *const instabot_keywords[] = {"instabot"};
static const br_detector instabot_detector = {
    .type = 856, .version = 0, .name = "Instabot", .custom_name = "",
    .description = "Instabot is a service that provides automated social media interactions. Instabot API keys can be used to access and interact with the service programmatically.",
    .keywords = instabot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &instabot_pattern, .scan = instabot_scan,
};

int br_instabot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return instabot_fail(error, "invalid Instabot detector output");
    *out = NULL;
    if (!instabot_pattern && br_regex_compile_prefixed(instabot_keywords, 1,
        "\\b([0-9a-zA-Z=+\\/]{43}[0-9a-zA-Z+\\/=]{1})", &instabot_pattern, error) != 0)
        return -1;
    *out = &instabot_detector;
    return 0;
}
