/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/jotform/jotform.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { JOTFORM_ABORT = -1, JOTFORM_KEEP = 0, JOTFORM_DROP = 1 } jotform_outcome;

static int jotform_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static jotform_outcome jotform_verify(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    static const char prefix[] = "https://api.jotform.com/user?apiKey=";
    if (key.len > SIZE_MAX - sizeof(prefix)) {
        jotform_fail(error, "Jotform URL too large");
        return JOTFORM_ABORT;
    }
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) {
        jotform_fail(error, "cannot construct Jotform URL");
        return JOTFORM_ABORT;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* Finding and the literal query exist before NewRequestWithContext.
     * A nil context is a constructor failure: drop, do not send or release. */
    if (!ctx) {
        free(url);
        return JOTFORM_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Do and shared preparation failures stay unverified. Source never reads
     * the body, so a read error cannot change status or publication. No setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return JOTFORM_KEEP;
}

static int jotform_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return jotform_fail(error, "invalid or uninitialized Jotform scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        jotform_outcome outcome = JOTFORM_KEEP;
        /* TrimSpace cannot change this class. Keep ordered duplicates.
         * Do not use br_scan_key: a constructor drop must not be published. */
        if (key.len != 32) {
            jotform_fail(&owned_error, "invalid Jotform capture");
            outcome = JOTFORM_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            jotform_fail(&owned_error, "cannot create Jotform result");
            outcome = JOTFORM_ABORT;
        } else if (verify) {
            outcome = jotform_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == JOTFORM_KEEP && br_results_push(out, &result) != 0) {
            jotform_fail(&owned_error, "cannot append Jotform result");
            outcome = JOTFORM_ABORT;
        }
        br_result_clear(&result);
        if (outcome == JOTFORM_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const jotform_keywords[] = {"jotform"};
static br_detector jotform_detector = {
    .type = 287, .version = 0, .name = "Jotform", .custom_name = "",
    .description = "Jotform is an online form builder and survey tool. Jotform API keys can be used to access and manage form submissions and data.",
    .keywords = jotform_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = jotform_scan,
};

int br_jotform_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return jotform_fail(error, "invalid Jotform detector output");
    *out = NULL;
    if (br_key_pattern_init(&jotform_detector, "\\b([0-9Aa-z]{32})\\b", error) != 0)
        return -1;
    *out = &jotform_detector;
    return 0;
}
