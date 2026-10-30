/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/prefect/prefect.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int prefect_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int prefect_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return prefect_fail(error, "invalid or uninitialized Prefect scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = prefect_fail(&owned_error, "cannot create Prefect result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.prefect.cloud/auth/login";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            char value[sizeof("Bearer ") + 40];
            memcpy(value, "Bearer ", sizeof("Bearer ") - 1);
            memcpy(value + sizeof("Bearer ") - 1, key.data, 40);
            value[sizeof(value) - 1] = '\0';
            const br_header headers[] = {{"Authorization", value}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = prefect_fail(&owned_error, "cannot append Prefect result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const prefect_keywords[] = {"pnu_"};
static br_regex *prefect_pattern;
static br_detector prefect_detector = {
    .type = 918, .version = 0, .name = "Prefect", .custom_name = "",
    .description = "Prefect is a workflow orchestration tool. Prefect API keys can be used to access and manage workflows and tasks.",
    .keywords = prefect_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = prefect_scan,
};

int br_prefect_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return prefect_fail(error, "invalid Prefect detector output");
    *out = NULL;
    /* The keyword is a dispatch hint only; the source pattern is unprefixed. */
    if (!prefect_pattern && br_regex_compile("\\b(pnu_[a-zA-Z0-9]{36})\\b", &prefect_pattern, error) != 0)
        return -1;
    prefect_detector.state = prefect_pattern;
    *out = &prefect_detector;
    return 0;
}
