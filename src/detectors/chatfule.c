/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/chatfule/chatfule.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int chatfule_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void chatfule_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[136] = "Bearer ";
    memcpy(auth + 7, key, 129); /* Exactly 128 captured ASCII bytes plus NUL. */
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://dashboard.chatfuel.com/api/bots",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 692,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1's one nonzero send domain
     * also conflates adapter allocation/setup failures, an explicit partial
     * gap. No text classification or verification-error setter is used. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without draining. ABI1 eagerly releases
     * each request and may already have buffered the body. Body errors ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int chatfule_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return chatfule_fail(error, "invalid or uninitialized Chatfule scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII captures leave nil context as the known
         * constructor failure. Source skips, rather than appending a finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op for this captured ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = chatfule_fail(error, "out of memory creating Chatfule result");
        else if (verify) chatfule_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = chatfule_fail(error, "out of memory appending Chatfule result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

/* Upstream PB/package identity is Chatfule; the actual brand/keyword is Chatfuel. */
static const char *const chatfule_keywords[] = {"chatfuel"};
static br_detector chatfule_detector = {
    .type = 692, .version = 0, .name = "Chatfule", .custom_name = "",
    .description = "Chatfuel is a platform for creating chatbots for Facebook Messenger and other platforms. "
                   "Chatfuel API keys can be used to access and manage chatbot configurations and interactions.",
    .keywords = chatfule_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = chatfule_scan,
};

int br_chatfule_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return chatfule_fail(error, "invalid Chatfule detector output");
    *out = NULL;
    if (br_key_pattern_init(&chatfule_detector, "\\b([a-zA-Z0-9]{128})\\b", error) != 0) return -1;
    *out = &chatfule_detector;
    return 0;
}
