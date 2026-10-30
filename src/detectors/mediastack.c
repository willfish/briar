/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mediastack/mediastack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mediastack_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void mediastack_verify(const br_scan_ctx *ctx, const br_http_request *request,
                               br_result *result)
{
    br_http_response response = {0};
    char *send_error = NULL;
    /* The source suppresses the WHOLE mixed preparation/Do error domain and
     * never sets a verification error. Bodies/read errors are ignored. */
    if (br_http_send(ctx, request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* The original request/URL/key remain alive through one release per send;
     * synthesized prepared headers/UA instead end at ordinary send return. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int mediastack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mediastack_fail(error, "invalid or uninitialized MediaStack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace cannot alter the lowercase ASCII-alphanumeric capture.
         * Preserve each occurrence and key-only metadata without filtering. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = mediastack_fail(&owned_error, "cannot create MediaStack finding");
        if (rc == 0 && verify) {
            /* Source sets client.Timeout BEFORE URL construction and the
             * constructor. Project it request-locally, without a shared race:
             * this is still SANE transport policy, not the PUBLIC profile. */
            const uint32_t timeout_ms = 10000;
            const char prefix[] = "https://api.mediastack.com/v1/news?access_key=";
            char url[sizeof(prefix) + 32];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, keys.items[i], 32);
            url[sizeof(url) - 1] = '\0';
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .timeout_ms = timeout_ms, .detector_type = detector->type,
            };
            /* The complete literal URL precedes the nil-context skip. */
            if (!ctx) { br_result_clear(&result); continue; }
            mediastack_verify(ctx, &request, &result);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mediastack_fail(&owned_error, "cannot append MediaStack finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        mediastack_fail(&owned_error, "cannot collect MediaStack keys");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mediastack_keywords[] = {"mediastack"};
static br_detector mediastack_detector = {
    .type = 531, .version = 0, .name = "MediaStack", .custom_name = "",
    .description = "MediaStack is a service that provides real-time news data. MediaStack API keys can be used to access this data.",
    .keywords = mediastack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mediastack_scan,
};

int br_mediastack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mediastack_fail(error, "invalid MediaStack detector output");
    *out = NULL;
    if (!mediastack_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(mediastack_keywords, 1, "\\b([a-z0-9]{32})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        mediastack_detector.state = pattern;
    }
    *out = &mediastack_detector;
    return 0;
}
