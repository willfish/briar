/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rubygems/rubygems.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int rubygems_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int rubygems_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return rubygems_fail(error, "invalid or uninitialized RubyGems scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 57 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = rubygems_fail(&owned_error, "cannot create RubyGems result");
        if (rc == 0 && verify) {
            static const char url[] = "https://rubygems.org/api/v1/gems.json";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            static const char h0[] = "*/*";
            const char *h1 = (const char *)key.data;
            const br_header headers[] = {{"Accept", h0}, {"Authorization", h1}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = (response.status >= 200 && response.status < 300) || response.status == 403;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = rubygems_fail(&owned_error, "cannot append RubyGems result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rubygems_keywords[] = {"rubygems"};
static br_regex *rubygems_pattern;
static br_detector rubygems_detector = {
    .type = 200, .version = 0, .name = "RubyGems", .custom_name = "",
    .description = "RubyGems is a package manager for the Ruby programming language. RubyGems API keys can be used to publish and manage gems (libraries) on the RubyGems platform.",
    .keywords = rubygems_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = rubygems_scan,
};

int br_rubygems_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rubygems_fail(error, "invalid RubyGems detector output");
    *out = NULL;
    /* The keyword is a dispatch hint only; the source pattern is unprefixed. */
    if (!rubygems_pattern && br_regex_compile("\\b(rubygems_[a-zA0-9]{48})\\b", &rubygems_pattern, error) != 0)
        return -1;
    rubygems_detector.state = rubygems_pattern;
    *out = &rubygems_detector;
    return 0;
}
