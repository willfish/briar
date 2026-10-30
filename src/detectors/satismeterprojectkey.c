/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/satismeterprojectkey/satismeterprojectkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { SAT_ABORT = -1, SAT_KEEP = 0 } sat_outcome;

static int sat_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static sat_outcome sat_verify(const br_scan_ctx *ctx, br_slice project, br_slice token,
                              br_result *result, char **error)
{
    const char *cause = NULL;
    char *transport_error = NULL;
    br_http_response response = {0};
    char status[64] = {0};
    char url[sizeof("https://app.satismeter.com/api/users?project=") + 24];
    char authorization[7 + 32 + 1];
    int written = snprintf(url, sizeof(url), "https://app.satismeter.com/api/users?project=%.*s",
                           (int)project.len, (const char *)project.data);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        sat_fail(error, "cannot build SatismeterProjectkey URL");
        return SAT_ABORT;
    }
    /* The complete URL is built before NewRequestWithContext. The project
     * class cannot make it fail to parse. Nil context sets the error and the
     * pair is still published. */
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        memcpy(authorization, "Bearer ", 7);
        memcpy(authorization + 7, token.data, token.len);
        authorization[7 + token.len] = '\0';
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        /* Exactly 200 verifies. Other statuses, including 401, are unverified
         * with a nil error. Body and read errors are ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status == 200)
            result->verified = true;
        else if (response.status != 401 && response.status != 403 && response.status != 404) {
            snprintf(status, sizeof(status), "unexpected status code: %d", response.status);
            cause = status;
        }
    }
    br_slice secret = {token.data, token.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) {
        sat_fail(error, "cannot set SatismeterProjectkey verification error");
        return SAT_ABORT;
    }
    return SAT_KEEP;
}

static int sat_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sat_fail(error, "invalid or uninitialized SatismeterProjectkey scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures projects = {0}, tokens = {0};
    char *owned_error = NULL;
    /* Unique project ids and tokens. Map order is unspecified upstream; first
     * seen is one possible order. Every project is paired with every token. */
    int rc = br_captures_find(patterns[0], input, &projects, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < projects.len; ++i) {
        br_slice project = br_captures_at(&projects, i);
        if (project.len != 24) {
            sat_fail(&owned_error, "invalid SatismeterProjectkey project capture");
            rc = -1;
            break;
        }
        for (size_t j = 0; j < tokens.len; ++j) {
            br_slice token = br_captures_at(&tokens, j);
            br_result result = {0};
            sat_outcome outcome = SAT_KEEP;
            if (token.len != 32) {
                sat_fail(&owned_error, "invalid SatismeterProjectkey token capture");
                outcome = SAT_ABORT;
            } else if (br_finding_pair_bytes(&result, detector->type, project, "project_id",
                                             token, "token", (br_slice){0}) != 0) {
                sat_fail(&owned_error, "cannot create SatismeterProjectkey result");
                outcome = SAT_ABORT;
            } else if (verify) {
                outcome = sat_verify(ctx, project, token, &result, &owned_error);
            }
            if (outcome == SAT_KEEP && br_results_push(out, &result) != 0) {
                sat_fail(&owned_error, "cannot append SatismeterProjectkey result");
                outcome = SAT_ABORT;
            }
            br_result_clear(&result);
            if (outcome == SAT_ABORT) {
                rc = -1;
                break;
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&projects);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sat_keywords[] = {"satismeter"};
static br_regex *sat_patterns[2];
static br_detector sat_detector = {
    .type = 230, .version = 0, .name = "SatismeterProjectkey", .custom_name = "",
    .description = "Satismeter is a customer feedback platform. Satismeter project keys can be used to access project-specific data and manage feedback settings.",
    .keywords = sat_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = sat_scan, .state = sat_patterns,
};

int br_satismeterprojectkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sat_fail(error, "invalid SatismeterProjectkey detector output");
    *out = NULL;
    if (!sat_patterns[0]) {
        const char *const prefix[] = {"satismeter"};
        if (br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-zA-Z]{24})\\b", &sat_patterns[0], error) != 0 ||
            br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-zA-Z]{32})\\b", &sat_patterns[1], error) != 0)
            return -1;
    }
    *out = &sat_detector;
    return 0;
}
