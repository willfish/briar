/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/airbrakeuserkey/airbrakeuserkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_airbrakeuserkey(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128];
    snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects?key=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 126,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the body but ignores both errors. */
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
    /* Upstream supplies no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_airbrakeuserkey(const br_detector *detector, const br_scan_ctx *ctx,
                                bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AirbrakeUserKey scan arguments");
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, true, error);
    /* Upstream iterates a unique-key map; finding order is unspecified. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_json *guide = NULL;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            goto memory_error;
        result.extra_data = json_object_new_object();
        guide = json_object_new_string("https://howtorotate.com/docs/tutorials/airbrake/");
        if (!result.extra_data || !guide ||
            json_object_object_add(result.extra_data, "rotation_guide", guide) != 0)
            goto memory_error;
        guide = NULL; /* ExtraData owns the string. */
        if ((verify && verify_airbrakeuserkey(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0)
            goto memory_error;
        continue;
    memory_error:
        json_object_put(guide);
        br_result_clear(&result);
        rc = fail(error, "out of memory creating AirbrakeUserKey result");
    }
    br_captures_clear(&keys);
    return rc;
}

static const char *const keywords[] = {"airbrake"};
static br_detector airbrakeuserkey = {
    .type = 126, .version = 0, .name = "AirbrakeUserKey", .custom_name = "",
    .description = "Airbrake is an error and performance monitoring service. "
                   "Airbrake User Keys can be used to access and manage error reports and performance data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_airbrakeuserkey,
};

int br_airbrakeuserkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AirbrakeUserKey detector output");
    *out = NULL;
    if (!airbrakeuserkey.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z-0-9]{40})\\b", &regex, error) != 0)
            return -1;
        airbrakeuserkey.state = regex;
    }
    *out = &airbrakeuserkey;
    return 0;
}
