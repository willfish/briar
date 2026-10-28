/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getemail/getemail.go. */
#include "key_scan.h"
#include "captures.h"
#include "findings.h"
#include "../http_internal.h"

#include <stdlib.h>
#include <string.h>

static int getemail_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool getemail_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://api.getemail.io/v1/find-mail?firstname=Larry&lastname=Page&domain=google.com&api_key=";
    char url[sizeof(prefix) + 20];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 20);
    url[sizeof(url) - 1] = '\0';
    /* The complete bounded literal precedes NewRequestWithContext's nil-context
     * rejection. The capture alphabet needs no URL escaping or validation. */
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool keep = true;
    /* SaneHttpClientTimeOut uses Go DefaultTransport, NOT saneTransport.
     * This private helper permits knowingly injected bytes only; SANE/5000
     * projects common preparation, not native transport-policy equivalence. */
    if (br_http_default_transport_5s_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error) keep = false;
        else {
            static const unsigned char marker[] = "\"code\":\"USER_NOT_EXIST\"";
            result->verified = response.status >= 200 && response.status < 300 &&
                br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) == SIZE_MAX;
        }
    }
    /* Shared setup/Do failures keep a false result without a setter. Release
     * once even on failure/drop. Only this provider URL survives release;
     * ordinary synthesized headers/UA end at send return. Source defers close. */
    br_http_release(ctx, &response);
    free(transport_error);
    return keep;
}

static int getemail_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getemail_fail(error, "invalid or uninitialized GetEmail scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* Source TrimSpace is a no-op for this ASCII capture alphabet. Build
         * owned findings before constructor SKIP or body-read DROP decisions. */
        if (key.len != 20) rc = getemail_fail(&owned_error, "invalid GetEmail capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = getemail_fail(&owned_error, "cannot create GetEmail result");
        if (rc == 0 && (!verify || getemail_verify(ctx, key, &result)) &&
            br_results_push(out, &result) != 0)
            rc = getemail_fail(&owned_error, "cannot append GetEmail result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const getemail_keywords[] = {"getemail"};
static br_detector getemail_detector = {
    .type = 326, .version = 0, .name = "GetEmail", .custom_name = "",
    .description = "GetEmail is a service used to find email addresses based on names and domains. GetEmail API keys can be used to access and retrieve email addresses.",
    .keywords = getemail_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = getemail_scan,
};

int br_getemail_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getemail_fail(error, "invalid GetEmail detector output");
    *out = NULL;
    if (br_key_pattern_init(&getemail_detector, "\\b([a-zA-Z0-9-]{20})\\b", error) != 0) return -1;
    *out = &getemail_detector;
    return 0;
}
