/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/chatbot/chatbot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_chatbot(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char auth[40]; /* Bearer + SPACE + exactly 32 captured ASCII bytes + NUL. */
    int n = snprintf(auth, sizeof(auth), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return fail(error, "cannot format Chatbot Authorization header");
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {.method = "GET", .url = "https://api.chatbot.com/stories",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 208};
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All Do errors are suppressed. ABI1 also mixes adapter allocation/setup
     * failures into this nonzero domain; never infer their stage from text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close-only until scan return without draining. ABI1 may
     * already have buffered the body and releases per request instead. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0; /* No verification-error setter, even for non-2xx or Do failures. */
}

static int scan_chatbot(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Chatbot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the known
         * constructor failure. Source skips the candidate, not the invocation. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* Capture alphabet excludes whitespace: source TrimSpace is a no-op. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating Chatbot result");
        else if (verify) rc = verify_chatbot(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Chatbot result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"chatbot"};
static br_detector chatbot = {
    .type = 208, .version = 0, .name = "Chatbot", .custom_name = "",
    .description = "Chatbot API keys are used to interact with the Chatbot service, allowing access to create, modify, and retrieve chatbot stories and other resources.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_chatbot,
};

int br_chatbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Chatbot detector output");
    *out = NULL;
    if (br_key_pattern_init(&chatbot, "\\b([a-zA-Z0-9_]{32})\\b", error) != 0) return -1;
    *out = &chatbot;
    return 0;
}
