/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aeroworkflow/aeroworkflow.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } aeroworkflow_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_aeroworkflow(const br_scan_ctx *ctx, const char *key,
                               const char *id, br_result *result)
{
    static const char prefix[] = "https://api.aeroworkflow.com/api/";
    static const char suffix[] = "/me";
    size_t id_len = strlen(id), fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (id_len > SIZE_MAX - fixed) return -1;
    char *url = malloc(fixed + id_len);
    if (!url) return -1;
    snprintf(url, fixed + id_len, "%s%s%s", prefix, id, suffix);
    const br_header headers[] = {{"Accept", "application/json"}, {"apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 693,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Accepting JSON does not imply reading it: upstream checks only status. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream redacts only the API key, not the account ID. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(url);
    return rc;
}

static int scan_aeroworkflow(const br_detector *detector, const br_scan_ctx *ctx,
                             bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Aeroworkflow scan arguments");
    const aeroworkflow_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id)
        return fail(error, "uninitialized Aeroworkflow detector");
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(compiled->id, input, &ids, false, error);
    /* Capture alphabets exclude whitespace, so TrimSpace changes neither part.
     * Both lists retain occurrences: keys are outermost in the Cartesian product. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0 ||
                (verify && verify_aeroworkflow(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating Aeroworkflow result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static aeroworkflow_patterns patterns;
static const char *const keywords[] = {"aeroworkflow"};
static const br_detector aeroworkflow = {
    .type = 693, .version = 0, .name = "Aeroworkflow", .custom_name = "",
    .description = "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys "
                   "and Account IDs can be used to access and manage workflows.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_aeroworkflow,
};

int br_aeroworkflow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Aeroworkflow detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9^!?#:*;]{20})", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9]{1,})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &aeroworkflow;
    return 0;
}
