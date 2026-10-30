/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sendbirdorganizationapi/sendbirdorganizationapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sendbird_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sendbird_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    const char *cause = NULL;
    char *transport_error = NULL;
    br_http_response response = {0};
    char token[24 + 1];
    char status[64] = {0};
    memcpy(token, key.data, key.len);
    token[key.len] = '\0';
    /* Header.Add canonicalizes this all-caps name before Do. Briar does not. */
    const br_header headers[] = {{"Sendbirdorganizationapitoken", token}};
    const br_http_request request = {
        .method = "GET", .url = "https://gate.sendbird.com/api/v2/applications",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    /* The source sets the constructor error and then still uses the request.
     * A nil context is therefore fatal after the setter, and this invocation
     * rolls back. The fixed URL cannot fail to parse. */
    if (!ctx) cause = "net/http: nil Context";
    else if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 403) {
        snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
        cause = status;
    }
    br_slice secret = {key.data, key.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) return sendbird_fail(error, "cannot set SendbirdOrganizationAPI verification error");
    if (!ctx) return sendbird_fail(error, "net/http: nil Context");
    return 0;
}

static int sendbird_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sendbird_fail(error, "invalid or uninitialized SendbirdOrganizationAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Prefix is sendbirdorgapi, not the keyword sendbird. Ordered duplicates stay. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 24) {
            sendbird_fail(&owned_error, "invalid SendbirdOrganizationAPI capture");
            rc = -1;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            sendbird_fail(&owned_error, "cannot create SendbirdOrganizationAPI result");
            rc = -1;
        } else if (verify && sendbird_verify(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            sendbird_fail(&owned_error, "cannot append SendbirdOrganizationAPI result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sendbird_keywords[] = {"sendbird"};
static br_detector sendbird_detector = {
    .type = 751, .version = 0, .name = "SendbirdOrganizationAPI", .custom_name = "",
    .description = "Sendbird is a chat and messaging platform. Sendbird API tokens can be used to access and manage Sendbird applications and services.",
    .keywords = sendbird_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sendbird_scan,
};

int br_sendbirdorganizationapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sendbird_fail(error, "invalid SendbirdOrganizationAPI detector output");
    *out = NULL;
    if (!sendbird_detector.state) {
        const char *const prefix[] = {"sendbird"};
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-f]{24})\\b", &pattern, error) != 0)
            return -1;
        sendbird_detector.state = pattern;
    }
    *out = &sendbird_detector;
    return 0;
}
