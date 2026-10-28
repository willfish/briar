/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/googlegemini/googlegemini.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int googlegemini_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int googlegemini_verify(const br_scan_ctx *ctx, const char *key,
                              br_result *result, char **error)
{
    char *cause = NULL;
    bool active = false, verified = false;
    if (!ctx) {
        /* SetVerificationError unwraps the known constructor wrapper. */
        cause = strdup("net/http: nil Context");
        if (!cause) return googlegemini_fail(error, "cannot create Google Gemini cause");
    } else {
        const br_header headers[] = {
            {"Content-Type", "application/json"}, {"X-Goog-Api-Key", key},
        };
        const br_http_request request = {
            .method = "GET", .url = "https://generativelanguage.googleapis.com/v1/models",
            .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        int rc = br_http_send(ctx, &request, &response, &cause);
        bool cause_failed = false;
        if (rc == 0) {
            switch (response.status) {
            case 200: verified = true; active = true; break;
            case 403: active = true; break;
            case 400: break;
            default: {
                char message[64];
                int n = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
                if (n < 0 || (size_t)n >= sizeof(message)) cause_failed = true;
                else {
                    free(cause);
                    cause = strdup(message);
                    cause_failed = !cause;
                }
                break;
            }
            }
        }
        /* Ignore every body/read error. Only original provider values survive
         * release; ordinary ABI1 synthesized headers end at send return. */
        br_http_release(ctx, &response);
        if (cause_failed) {
            free(cause);
            return googlegemini_fail(error, "cannot create Google Gemini cause");
        }
    }
    /* Preserve FromData's Verified -> ExtraData -> setter order. */
    result->verified = verified;
    if (active) {
        result->extra_data = json_object_new_object();
        br_json *value = json_object_new_string("true");
        if (!result->extra_data || !value) {
            if (value) json_object_put(value);
            free(cause);
            return googlegemini_fail(error, "cannot create Google Gemini metadata");
        }
        if (json_object_object_add(result->extra_data, "active_google_key", value) != 0) {
            json_object_put(value);
            free(cause);
            return googlegemini_fail(error, "cannot create Google Gemini metadata");
        }
    }
    /* The source supplies zero redaction arguments, even for transport errors. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    free(cause);
    if (rc != 0) return googlegemini_fail(error, "cannot set Google Gemini verification error");
    return 0;
}

static int googlegemini_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return googlegemini_fail(error, "invalid or uninitialized Google Gemini scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* TrimSpace is a no-op. Retain original occurrences and duplicates. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = googlegemini_fail(&owned_error, "cannot create Google Gemini result");
        if (rc == 0) {
            result.redacted = malloc(12);
            if (!result.redacted) rc = googlegemini_fail(&owned_error, "cannot redact Google Gemini result");
            else {
                memcpy(result.redacted, key.data, 8);
                memcpy(result.redacted + 8, "...", 4);
            }
        }
        if (rc == 0 && verify)
            rc = googlegemini_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = googlegemini_fail(&owned_error, "cannot append Google Gemini result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const googlegemini_keywords[] = {"aizasy"};
static br_detector googlegemini_detector = {
    .type = 1041, .version = 0, .name = "GoogleGeminiAPIKey", .custom_name = "",
    .description = "Google Gemini API provides access to Google's latest generative AI models for building applications that understand and generate text, images, audio, and code with high performance and low latency.",
    .keywords = googlegemini_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = googlegemini_scan,
};

int br_googlegemini_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return googlegemini_fail(error, "invalid Google Gemini detector output");
    *out = NULL;
    if (!googlegemini_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(AIzaSy[A-Za-z0-9_-]{33})", &regex, error) != 0) return -1;
        googlegemini_detector.state = regex;
    }
    *out = &googlegemini_detector;
    return 0;
}
