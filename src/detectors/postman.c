/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/postman/postman.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int postman_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* Always invoke the checked setter, including a NULL cause. */
static int postman_commit(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return postman_fail(error, "cannot store Postman verification error");
    return 0;
}

static int postman_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char url[] = "https://api.getpostman.com/collections";
    if (!ctx) {
        /* Constructor failure is an ordinary cause, not a drop. */
        return postman_commit(result, "net/http: nil Context", key, error);
    }
    const br_header headers[] = {{"x-api-key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 118,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status == 200) {
        result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = postman_fail(error, "cannot format Postman status cause");
        else cause = status_error;
    }
    /* One release before the setter; the original key stays alive. */
    br_http_release(ctx, &response);
    if (rc == 0) rc = postman_commit(result, cause, key, error);
    free(send_error);
    return rc;
}

static int postman_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return postman_fail(error, "invalid or uninitialized Postman scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 64 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = postman_fail(&owned_error, "cannot create Postman result");
        if (rc == 0 && verify) rc = postman_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = postman_fail(&owned_error, "cannot append Postman result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const postman_keywords[] = {"PMAK-"};
static br_regex *postman_pattern;
static br_detector postman_detector = {
    .type = 118, .version = 0, .name = "Postman", .custom_name = "",
    .description = "Postman is a collaboration platform for API development. Postman API keys can be used to access and modify collections, environments, and other resources.",
    .keywords = postman_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = NULL,
    .scan = postman_scan,
};

int br_postman_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return postman_fail(error, "invalid Postman detector output");
    *out = NULL;
    /* The keyword is a dispatch hint only; the source pattern is unprefixed. */
    if (!postman_pattern &&
        br_regex_compile("\\b(PMAK-[a-zA-Z-0-9]{59})\\b", &postman_pattern, error) != 0)
        return -1;
    postman_detector.state = postman_pattern;
    *out = &postman_detector;
    return 0;
}
