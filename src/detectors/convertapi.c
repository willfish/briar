/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/convertapi/convertapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int convertapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int convertapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, char **error)
{
    /* The capture is exactly 23 unreserved bytes. Borrow the complete bounded
     * URL, including its NUL, through synchronous send AND release. */
    char url[sizeof("https://v2.convertapi.com/user?auth=") + 23];
    int n = snprintf(url, sizeof(url), "https://v2.convertapi.com/user?auth=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url))
        return convertapi_fail(error, "cannot format ConvertApi URL");
    /* Source formats the URL before NewRequestWithContext's known nil-context
     * failure. Only that constructor failure skips the candidate. */
    if (!ctx) {
        *keep = false;
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * failures here: suppress the whole domain, without text classification. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Eager buffering,
     * per-request ABI release, full native-client and global parity remain partial.
     * Body bytes/read errors never affect this status-only decision. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int convertapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return convertapi_fail(error, "invalid or uninitialized ConvertApi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op for this grammar. Preserve every occurrence and
         * prepare finding resources before URL formatting or constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = convertapi_fail(&owned_error, "cannot create ConvertApi result");
        if (rc == 0 && verify && convertapi_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = convertapi_fail(&owned_error, "cannot append ConvertApi result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const convertapi_keywords[] = {"convertapi"};
static br_detector convertapi_detector = {
    .type = 831, .version = 0, .name = "ConvertApi", .custom_name = "",
    .description = "ConvertAPI is a service that provides file conversion capabilities via API. "
                   "ConvertAPI keys can be used to access and perform file conversions.",
    .keywords = convertapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = convertapi_scan,
};

int br_convertapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return convertapi_fail(error, "invalid ConvertApi detector output");
    *out = NULL;
    /* Only PrefixRegex's keyword is case-insensitive; secret_ stays lowercase. */
    if (br_key_pattern_init(&convertapi_detector, "\\b(secret_[0-9a-zA-Z]{16})\\b", error) != 0)
        return -1;
    *out = &convertapi_detector;
    return 0;
}
