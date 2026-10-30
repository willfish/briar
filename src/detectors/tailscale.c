/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tailscale/tailscale.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.tailscale.com/api/v2/secret-scanning/verify";

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

static int verify_tailscale(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len > SIZE_MAX - 5) return -1;
    char *body = malloc(key.len + 5);
    if (!body) return -1;
    memcpy(body, "key=", 4);
    memcpy(body + 4, key.data, key.len);
    body[4 + key.len] = '\0';
    /* The form body is an argument to NewRequest. A nil context skips. */
    if (!ctx) {
        free(body);
        return 1;
    }
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {(unsigned char *)body, 4 + key.len}, .profile = BR_HTTP_SANE,
        .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 204) verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    result->verified = verified;
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    free(body);
    return rc;
}

static int scan_tailscale(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Tailscale scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int skip = 0;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Tailscale result");
        else if (verify) skip = verify_tailscale(ctx, key, &result);
        if (skip < 0) rc = fail(&owned_error, "cannot verify Tailscale candidate");
        if (!rc && !skip && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append Tailscale result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"tskey-", "tskey-api-", "tskey-oauth-"};
static br_detector detector = {
    .type = 929, .name = "Tailscale", .custom_name = "",
    .description = "Tailscale is a zero-config VPN for building secure networks. Tailscale API keys can be used to authenticate and interact with the Tailscale API.",
    .keywords = keywords, .nkeywords = 3, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_tailscale,
};

int br_tailscale_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Tailscale detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile("\\b(tskey-[a-z]+-[0-9A-Za-z_]+-[0-9A-Za-z_]+)\\b",
                         (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
