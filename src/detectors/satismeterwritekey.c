/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/satismeterwritekey/satismeterwritekey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int satis_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* encoding/json sorts map keys and escapes only &, <, >. This grammar has none. */
static int satis_payload(br_slice write_key, br_slice project, char **body, size_t *len)
{
    static const char head[] = "{\"event\":\"This is the event name\",\"project\":\"";
    static const char mid[] = "\",\"type\":\"track\",\"userId\":\"007\",\"writeKey\":\"";
    static const char tail[] = "\"}";
    _Static_assert(sizeof(head) - 1 == 45 && sizeof(mid) - 1 == 44 && sizeof(tail) - 1 == 2,
                   "Satismeter payload literals");
    if (project.len > SIZE_MAX - (sizeof(head) - 1 + sizeof(mid) - 1 + sizeof(tail) - 1) ||
        write_key.len > SIZE_MAX - (sizeof(head) - 1 + sizeof(mid) - 1 + sizeof(tail) - 1 + project.len))
        return -1;
    size_t n = sizeof(head) - 1 + project.len + sizeof(mid) - 1 + write_key.len + sizeof(tail) - 1;
    char *owned = malloc(n);
    if (!owned) return -1;
    char *p = owned;
    memcpy(p, head, sizeof(head) - 1); p += sizeof(head) - 1;
    memcpy(p, project.data, project.len); p += project.len;
    memcpy(p, mid, sizeof(mid) - 1); p += sizeof(mid) - 1;
    memcpy(p, write_key.data, write_key.len); p += write_key.len;
    memcpy(p, tail, sizeof(tail) - 1);
    *body = owned;
    *len = n;
    return 0;
}

static int satis_cause(br_result *result, const char *cause, br_slice write_key, char **error)
{
    if (br_result_set_verification_error(result, cause, &write_key, 1) != 0)
        return satis_fail(error, "cannot store Satismeter verification error");
    return 0;
}

static int satis_verify(const br_scan_ctx *ctx, br_slice project, br_slice write_key, br_slice token,
                        br_result *result, char **error)
{
    char *body = NULL;
    size_t body_len = 0;
    if (satis_payload(write_key, project, &body, &body_len) != 0)
        return satis_fail(error, "cannot allocate Satismeter payload");
    int rc = 0;
    if (!ctx) {
        rc = satis_cause(result, "net/http: nil Context", write_key, error);
        free(body);
        return rc;
    }
    if (token.len > INT_MAX) {
        free(body);
        return satis_fail(error, "Satismeter token too large");
    }
    char *authorization = malloc(7 + token.len + 1);
    if (!authorization) {
        free(body);
        return satis_fail(error, "cannot allocate Satismeter Authorization");
    }
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://app.satismeter.com/api/users?type=track",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, body_len},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        char status[64];
        const char *cause = NULL;
        if (response.status == 204) result->verified = true;
        else if (response.status != 401 && response.status != 403) {
            snprintf(status, sizeof(status), "unexpected status code: %d", response.status);
            cause = status;
        }
        /* Do errors are discarded. Body drain and close errors are ignored. */
        rc = satis_cause(result, cause, write_key, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    free(body);
    return rc;
}

static int satis_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !patterns[2] || !out ||
        (!input.data && input.len))
        return satis_fail(error, "invalid or uninitialized SatismeterWritekey scan");
    size_t original_len = out->len;
    br_captures projects = {0}, write_keys = {0}, tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &projects, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &write_keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[2], input, &tokens, true, &owned_error);
    /* First-seen order. Go map order is unstable; equality still skips. */
    for (size_t p = 0; rc == 0 && p < projects.len; ++p) {
        for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
            for (size_t w = 0; rc == 0 && w < write_keys.len; ++w) {
                br_slice project = br_captures_at(&projects, p);
                br_slice token = br_captures_at(&tokens, t);
                br_slice write_key = br_captures_at(&write_keys, w);
                if (token.len == write_key.len && !memcmp(token.data, write_key.data, token.len))
                    continue;
                br_result result = {0};
                if (br_finding_pair_bytes(&result, detector->type, project, "project_id",
                                          write_key, "write_key", (br_slice){0}) != 0)
                    rc = satis_fail(&owned_error, "cannot create SatismeterWritekey result");
                else if (verify)
                    rc = satis_verify(ctx, project, write_key, token, &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = satis_fail(&owned_error, "cannot append SatismeterWritekey result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&projects);
    br_captures_clear(&write_keys);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const satis_keywords[] = {"satismeter"};
static const char *const satis_prefix[] = {"satismeter"};
static br_regex *satis_patterns[3];
static br_detector satis_detector = {
    .type = 231, .version = 0, .name = "SatismeterWritekey", .custom_name = "",
    .description = "Satismeter is a customer feedback platform. Satismeter Writekeys can be used to send event data to Satismeter's API.",
    .keywords = satis_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = satis_scan,
};

int br_satismeterwritekey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return satis_fail(error, "invalid SatismeterWritekey detector output");
    *out = NULL;
    if (!satis_patterns[0] &&
        br_regex_compile_prefixed(satis_prefix, 1, "\\b([a-zA-Z0-9]{24})\\b",
                                  &satis_patterns[0], error) != 0)
        return -1;
    if (!satis_patterns[1] &&
        br_regex_compile_prefixed(satis_prefix, 1, "\\b([a-z0-9A-Z]{32})\\b",
                                  &satis_patterns[1], error) != 0)
        return -1;
    if (!satis_patterns[2] &&
        br_regex_compile_prefixed(satis_prefix, 1, "\\b([A-Za-z0-9]{32})\\b",
                                  &satis_patterns[2], error) != 0)
        return -1;
    satis_detector.state = satis_patterns;
    *out = &satis_detector;
    return 0;
}
