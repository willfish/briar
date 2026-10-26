/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apptivo/apptivo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } apptivo_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_apptivo(const br_scan_ctx *ctx, const char *key,
                           const char *id, br_result *result)
{
    char url[sizeof("https://api.apptivo.com/app/dao/v6/leads?a=getConfigData&apiKey=&accessKey=") + 36 + 32];
    snprintf(url, sizeof(url),
             "https://api.apptivo.com/app/dao/v6/leads?a=getConfigData&apiKey=%s&accessKey=%s", key, id);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 269,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status != 200) {
        /* Even 401/403 are errors. Deferred body-drain/close errors are ignored. */
        snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
        cause = status_error;
    } else if (response.body_error) {
        /* ReadAll errors take precedence over any marker in a partial body. */
        cause = response.body_error;
    } else {
        static const unsigned char marker[] = "displayName";
        result->verified = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
    }
    const br_slice secrets[] = {
        {(const unsigned char *)key, strlen(key)},
        {(const unsigned char *)id, strlen(id)},
    };
    int rc = br_result_set_verification_error(result, cause, secrets, 2);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_apptivo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Apptivo scan arguments");
    const apptivo_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id)
        return fail(error, "uninitialized Apptivo detector");
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, error);
    /* Both alphabets exclude whitespace, so TrimSpace is a no-op. Preserve every
     * occurrence, including duplicates, in key-outer/ID-inner order. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0 ||
                (verify && verify_apptivo(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Apptivo result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static apptivo_patterns patterns;
static const char *const keywords[] = {"apptivo"};
static const br_detector apptivo = {
    .type = 269, .version = 0, .name = "Apptivo", .custom_name = "",
    .description = "Apptivo is a cloud-based suite of business solutions, including CRM, project "
                   "management, and more. Apptivo API keys can be used to access and manage these "
                   "services programmatically.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_apptivo,
};

int br_apptivo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Apptivo detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9-]{36})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9-]{32})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &apptivo;
    return 0;
}
