/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/messagebird/messagebird.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int messagebird_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's skip, not verification rejection. */
static bool messagebird_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    static const char prefix[] = "AccessKey ";
    char authorization[sizeof(prefix) + 25];
    /* Preserve all 25 original bytes literally. The bounded capture needs no
     * fallible formatter, encoder, normalization or alternate auth scheme. */
    memcpy(authorization, prefix, sizeof(prefix) - 1);
    memcpy(authorization + sizeof(prefix) - 1, key.data, key.len);
    authorization[sizeof(authorization) - 1] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://rest.messagebird.com/messages",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole mixed preparation/Do nonzero domain without diagnostic
     * classification. The source never calls a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors are ignored. Provider auth/header/key/URL remain live
     * through one release per attempt; synthesized prepared storage ends at send
     * return. ABI1 release differs from source scan-deferred Close scheduling. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int messagebird_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return messagebird_fail(error, "invalid or uninitialized MessageBird scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace is a no-op. Preserve case, underscores, hyphens, duplicates
         * and occurrence order. Findings precede the nil-context constructor skip. */
        if (key.len != 25)
            rc = messagebird_fail(&owned_error, "invalid MessageBird capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = messagebird_fail(&owned_error, "cannot create MessageBird finding");
        if (rc == 0 && verify) keep = messagebird_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = messagebird_fail(&owned_error, "cannot append MessageBird finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const messagebird_keywords[] = {"messagebird"};
static br_detector messagebird_detector = {
    .type = 111, .version = 0, .name = "MessageBird", .custom_name = "",
    .description = "MessageBird is a cloud communications platform. MessageBird API keys can be used to send and receive SMS, voice, and chat messages.",
    .keywords = messagebird_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = messagebird_scan,
};

int br_messagebird_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return messagebird_fail(error, "invalid MessageBird detector output");
    *out = NULL;
    if (!messagebird_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(messagebird_keywords, 1, "\\b([A-Za-z0-9_-]{25})\\b", &regex, error) != 0)
            return -1;
        messagebird_detector.state = regex;
    }
    *out = &messagebird_detector;
    return 0;
}
