/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/moderation/moderation.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int moderation_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static const unsigned char moderation_payload[] = "{\"value\": \"This is an english text\"}";
typedef struct moderation_pending moderation_pending;
struct moderation_pending {
    moderation_pending *next;
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    unsigned char *body;
    char *authorization;
};

static void moderation_release(const br_scan_ctx *ctx, moderation_pending *pending)
{
    while (pending) {
        moderation_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending->body);
        free(pending);
        pending = next;
    }
}

static int moderation_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              moderation_pending **pending, bool *keep, char **error)
{
    /* Source creates its strings.Reader before the fixed-URL constructor;
     * retain its exact body bytes, including spaces, before nil handling. */
    unsigned char *body = malloc(sizeof(moderation_payload));
    if (!body) return moderation_fail(error, "cannot construct Moderation body");
    memcpy(body, moderation_payload, sizeof(moderation_payload));
    if (!ctx) { free(body); *keep = false; return 0; }
    moderation_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) { free(body); return moderation_fail(error, "cannot construct Moderation request"); }
    *attempt = (moderation_pending){0}; attempt->body = body;
    attempt->authorization = malloc(7 + key.len + 1);
    if (!attempt->authorization) {
        free(body); free(attempt);
        return moderation_fail(error, "cannot construct Moderation authorization");
    }
    memcpy(attempt->authorization, "Bearer ", 7);
    memcpy(attempt->authorization + 7, key.data, key.len);
    attempt->authorization[7 + key.len] = 0;
    attempt->headers[0] = (br_header){"Authorization", attempt->authorization};
    attempt->headers[1] = (br_header){"Content-Type", "application/json"};
    attempt->request = (br_http_request){
        .method = "POST", .url = "https://moderationapi.com/api/v1/analyze/language",
        .headers = attempt->headers, .nheaders = 2,
        .body = {body, sizeof(moderation_payload) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        result->verified = attempt->response.status >= 200 && attempt->response.status < 300;
        attempt->next = *pending; *pending = attempt;
    } else {
        /* Source suppresses the whole mixed shared preparation/Do domain,
         * never classifying text or calling a verification-error setter. */
        moderation_release(ctx, attempt);
    }
    free(send_error);
    return 0;
}

static int moderation_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return moderation_fail(error, "invalid or uninitialized Moderation scan");
    size_t original_len = out->len;
    br_captures keys = {0}; moderation_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0}; bool keep = true;
        if (key.len != 196 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = moderation_fail(&owned_error, "cannot create Moderation result");
        if (rc == 0 && verify) rc = moderation_verify(ctx, key, &result, &pending, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = moderation_fail(&owned_error, "cannot append Moderation result");
        br_result_clear(&result);
    }
    /* All successful sends, including non-2xx, close scan-wide LIFO after
     * publication. Original request/auth/body/key live through release;
     * ordinary synthesized preparation ends at send return. Bodies are ignored. */
    moderation_release(ctx, pending);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const moderation_keywords[] = {"moderation"};
static br_detector moderation_detector = {
    .type = 669, .version = 0, .name = "Moderation", .custom_name = "",
    .description = "Moderation API keys are used to access the Moderation API, which provides services for analyzing and moderating content.",
    .keywords = moderation_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = moderation_scan,
};

int br_moderation_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return moderation_fail(error, "invalid Moderation detector output");
    *out = NULL;
    if (!moderation_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(moderation_keywords, 1,
            "\\b([a-zA-Z0-9]{36}\\.[a-zA-Z0-9]{115}\\.[a-zA-Z0-9_]{43})\\b", &regex, error) != 0) return -1;
        moderation_detector.state = regex;
    }
    *out = &moderation_detector;
    return 0;
}
