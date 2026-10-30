/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zerotier/zerotier.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.zerotier.com/api/v1/network";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int verify_zerotier(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    if (key.len != 32) return -1;
    char authorization[40];
    memcpy(authorization, "token ", 6);
    memcpy(authorization + 6, key.data, 32);
    authorization[38] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 200) verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    result->verified = verified;
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_zerotier(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ZeroTier scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source keeps every prefixed match; it does not collapse duplicates. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create ZeroTier result");
        else if (verify && verify_zerotier(ctx, key, &result))
            rc = fail(&owned_error, "cannot verify ZeroTier candidate");
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append ZeroTier result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"zerotier"};
static br_detector detector = {
    .type = 948, .name = "ZeroTier", .custom_name = "",
    .description = "ZeroTier is a network virtualization technology that provides secure and flexible network connections. ZeroTier API keys can be used to manage and control these network connections.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_zerotier,
};

int br_zerotier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ZeroTier detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-zA-Z]{32})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
