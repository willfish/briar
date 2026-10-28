/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/groq/groq.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int groq_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The helper closes its response before the caller assigns any result fields. */
static int groq_verify(const br_scan_ctx *ctx, br_slice key, bool *verified,
                       char **cause, char **error)
{
    *verified = false;
    *cause = NULL;
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        return *cause ? 0 : groq_fail(error, "cannot create Groq constructor cause");
    }
    /* Constructor precedes Authorization. The grammar bounds the entire token. */
    char auth[7 + 56 + 1];
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, key.data, 56);
    auth[63] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.groq.com/openai/v1/models",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 988,
    };
    br_http_response response = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, cause) != 0) {
        /* Retain the entire shared setup/Do domain without text classification. */
        if (!*cause) {
            *cause = strdup("HTTP transport failed");
            if (!*cause) rc = groq_fail(error, "cannot create Groq transport cause");
        }
    } else if (response.status == 200) *verified = true;
    else if (response.status != 401) {
        *cause = malloc(80);
        if (!*cause) rc = groq_fail(error, "cannot allocate Groq status cause");
        else {
            int n = snprintf(*cause, 80, "unexpected HTTP response status %d", response.status);
            if (n < 0 || n >= 80) rc = groq_fail(error, "cannot format Groq status cause");
        }
    }
    /* Ignore body/read errors at every status. Only original auth storage lives
     * through release, not ABI1's temporary prepared headers/User-Agent. */
    br_http_release(ctx, &response);
    return rc;
}

static int groq_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return groq_fail(error, "invalid or uninitialized Groq scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = groq_fail(&owned_error, "cannot create Groq finding");
        /* Source allocates this initial map even for verification/nil context. */
        if (rc == 0) {
            result.extra_data = json_object_new_object();
            br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/groq/");
            if (!result.extra_data || !guide) {
                json_object_put(guide);
                rc = groq_fail(&owned_error, "cannot create Groq rotation metadata");
            } else if (json_object_object_add(result.extra_data, "rotation_guide", guide) != 0) {
                json_object_put(guide);
                rc = groq_fail(&owned_error, "cannot store Groq rotation metadata");
            }
        }
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            rc = groq_verify(ctx, key, &verified, &cause, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                json_object_put(result.extra_data);
                result.extra_data = NULL;
                /* NULL cause is a no-op; every nonzero setter return is fatal. */
                if (br_result_set_verification_error(&result, cause, &key, 1) != 0)
                    rc = groq_fail(&owned_error, "cannot sanitize Groq verification error");
            }
            free(cause);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = groq_fail(&owned_error, "cannot append Groq finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const groq_keywords[] = {"gsk_"};
static br_detector groq_detector = {
    .type = 988, .version = 0, .name = "Groq", .custom_name = "",
    .description = "Groq is a company that creates data processing hardware and software. Groq API keys can be used to access their services.",
    .keywords = groq_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = groq_scan,
};

int br_groq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return groq_fail(error, "invalid Groq detector output");
    *out = NULL;
    if (!groq_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(gsk_[a-zA-Z0-9]{52})\\b", &regex, error) != 0) return -1;
        groq_detector.state = regex;
    }
    *out = &groq_detector;
    return 0;
}
