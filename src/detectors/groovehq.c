/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/groovehq/groovehq.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int groovehq_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's nil-context skip. */
static bool groovehq_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    /* Constructor precedes Authorization assembly. The grammar fixes the key
     * at 64 ASCII bytes, so the complete Bearer value needs no formatter. */
    char authorization[sizeof("Bearer ") - 1 + 64 + 1];
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key.data, 64);
    authorization[sizeof(authorization) - 1] = '\0';
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.groovehq.com/v1/me",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/allocation/Do domain, not selected
     * diagnostics. Body and read errors do not participate in verification. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Only original provider storage survives ordinary ABI1 send return. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int groovehq_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return groovehq_fail(error, "invalid or uninitialized Groovehq scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op for this grammar. Preserve original occurrences
         * and the first 64 bytes of longer tokens, without deduplication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = groovehq_fail(&owned_error, "cannot create Groovehq result");
        if (rc == 0 && verify) keep = groovehq_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = groovehq_fail(&owned_error, "cannot append Groovehq result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const groovehq_keywords[] = {"groovehq"};
static const char *const groovehq_prefix[] = {"groove"};
static br_detector groovehq_detector = {
    .type = 206, .version = 0, .name = "Groovehq", .custom_name = "",
    .description = "GrooveHQ is a simple help desk software. GrooveHQ API keys can be used to access and manage support tickets and customer interactions.",
    .keywords = groovehq_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = groovehq_scan,
};

int br_groovehq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return groovehq_fail(error, "invalid Groovehq detector output");
    *out = NULL;
    if (!groovehq_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(groovehq_prefix, 1, "\\b([a-z0-9A-Z]{64})", &regex, error) != 0)
            return -1;
        groovehq_detector.state = regex;
    }
    *out = &groovehq_detector;
    return 0;
}
