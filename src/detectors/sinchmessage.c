/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sinchmessage/sinchmessage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exact raw-string body, including the leading newline and tab indent. */
static const char sinch_body[] =
    "\n\t\t\t\t{\n\t\t\t\t\"from\": \"447537454435\",\n\t\t\t\t\"to\": [ \"639668957581\" ],\n"
    "\t\t\t\t\"body\": \"This is a test message from your Sinch account\"\n\t\t\t\t}";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_sinch(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SinchMessage scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source compiles the same pattern twice. One find is the same match list. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t id = 0; !rc && id < keys.len; ++id) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice service = br_captures_at(&keys, id);
            if (key.len != 32 || service.len != 32 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fail(&owned_error, "cannot create SinchMessage result");
            if (!rc && verify) {
                char url[96], authorization[48];
                int n = snprintf(url, sizeof(url), "https://sms.api.sinch.com/xms/v1/%.*s/batches",
                                 32, service.data);
                memcpy(authorization, "Bearer ", 7);
                memcpy(authorization + 7, key.data, 32);
                authorization[39] = '\0';
                if (n < 0 || (size_t)n >= sizeof(url)) {
                    br_result_clear(&result);
                    rc = fail(&owned_error, "cannot build SinchMessage URL");
                    break;
                }
                /* Body exists before NewRequestWithContext. Nil context skips this pair. */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                const br_header headers[] = {
                    {"Content-Type", "application/json"},
                    {"Authorization", authorization},
                };
                const br_http_request request = {
                    .method = "POST", .url = url, .headers = headers, .nheaders = 2,
                    .body = {(const unsigned char *)sinch_body, sizeof(sinch_body) - 1},
                    .profile = BR_HTTP_SANE, .detector_type = detector->type,
                };
                br_http_response response = {0};
                char *send_error = NULL;
                if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                    response.status >= 200 && response.status < 300)
                    result.verified = true;
                br_http_release(ctx, &response);
                free(send_error);
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append SinchMessage result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sinch"};
static br_detector sinch = {
    .type = 162, .version = 0, .name = "SinchMessage", .custom_name = "",
    .description = "Sinch is a cloud-based communications platform that enables businesses to send and receive messages, calls, and other communications. Sinch API keys can be used to access and manage these communication services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = scan_sinch,
};

int br_sinchmessage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SinchMessage detector output");
    *out = NULL;
    if (sizeof(sinch_body) - 1 != 131) return fail(error, "SinchMessage body drifted from source");
    if (br_key_pattern_init(&sinch, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &sinch;
    return 0;
}
