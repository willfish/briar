/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/airbrakeprojectkey/airbrakeprojectkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } airbrake_project_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_airbrake_project(const br_scan_ctx *ctx, const char *key,
                                   const char *id, br_result *result)
{
    static const unsigned char payload[] =
        "{\"environment\":\"production\",\"username\":\"john\",\"email\":\"john@smith.com\","
        "\"repository\":\"https://github.com/airbrake/airbrake\","
        "\"revision\":\"38748467ea579e7ae64f7815452307c9d05e05c5\",\"version\":\"v2.0\"}";
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.airbrake.io/api/v4/projects/%s/deploys?key=%s", id, key);
    /* Verification creates a deploy record. Upstream sets no Content-Type. */
    const br_http_request request = {
        .method = "POST", .url = url, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 125,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors while draining and closing the response body. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies no secrets to SetVerificationError. Never log the cause. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int add_rotation_guide(br_result *result)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/airbrake/");
    if (!guide) return -1;
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return -1;
    }
    return 0;
}

static int scan_airbrake_project(const br_detector *detector, const br_scan_ctx *ctx,
                                 bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AirbrakeProjectKey scan arguments");
    const airbrake_project_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return fail(error, "uninitialized AirbrakeProjectKey detector");

    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(patterns->key, input, &keys, true, error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, true, error);
    /* Upstream pairs independent unique sets, keys outermost. Go map order is
     * unspecified; first-seen capture order is sufficient for each native set. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                ids.items[i], "id") != 0 ||
                add_rotation_guide(&result) != 0 ||
                (verify && verify_airbrake_project(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AirbrakeProjectKey result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static airbrake_project_patterns patterns;
static const char *const keywords[] = {"airbrake"};
static const br_detector airbrake_project = {
    .type = 125, .version = 0, .name = "AirbrakeProjectKey", .custom_name = "",
    .description = "Airbrake is an error and performance monitoring service for web applications. "
                   "Airbrake project keys can be used to report and track errors in applications.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_airbrake_project,
};

int br_airbrakeprojectkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AirbrakeProjectKey detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z-0-9]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9]{6})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &airbrake_project;
    return 0;
}
