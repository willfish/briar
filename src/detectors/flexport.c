/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flexport/flexport.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int flexport_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int flexport_rotation(br_result *result)
{
    /* Each finding owns this map BEFORE verification, and retains it on EVERY
     * ordinary outcome. There is no verification-time metadata replacement. */
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *value = json_object_new_string("https://howtorotate.com/docs/tutorials/flexport/");
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "rotation_guide", value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int flexport_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return flexport_fail(error, "cannot set Flexport verification error");
        return 0; /* Constructor failure RETAINS false, its cause AND the guide. */
    }
    /* Header preparation follows construction. Direct private captures are
     * exactly 46 ASCII bytes, including their prefix; no formatter/heap copy. */
    char authorization[7 + 46 + 1];
    _Static_assert(sizeof(authorization) == 54, "Bearer value must be 53 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://logistics-api.flexport.com/logistics/api/2024-04/webhooks",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* Retain the WHOLE mixed shared setup/allocation/Do error domain as a
     * token-redacted leaf cause, without stripping or diagnostic classifiers. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200 || response.status == 403)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = flexport_fail(error, "cannot format Flexport verification status");
        else cause = status_error;
    }
    /* Exactly ONE redaction secret: the original token. NULL is a deliberate
     * no-op; all nonzero setter returns are fatal. Copy BEFORE release. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = flexport_fail(error, "cannot set Flexport verification error");
    /* Complete stack Authorization lives through BOTH send and release. Source
     * verifyMatch drains/closes and ignores body/read/drain errors. Eager body
     * buffering/release, Reader/drain/close timing, private override/default
     * clients, full native SANE/RE2, map order and global engine/output remain
     * parity gaps. ExtraData is NEVER cleared by verification. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int flexport_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flexport_fail(error, "invalid or uninitialized Flexport scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* Byte-original uniqueness. First-occurrence native order is one choice
     * of upstream's unspecified Go map order; no local filtering or cache. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = flexport_fail(&owned_error, "cannot create Flexport result");
        if (rc == 0 && flexport_rotation(&result) != 0)
            rc = flexport_fail(&owned_error, "cannot create Flexport rotation metadata");
        if (rc == 0 && verify) rc = flexport_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = flexport_fail(&owned_error, "cannot append Flexport result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flexport_keywords[] = {"shltm_"};
static br_detector flexport_detector = {
    .type = 1009, .version = 0, .name = "Flexport", .custom_name = "",
    .description = "Flexport is a global logistics company that provides shipping, freight forwarding, and supply chain management services.",
    .keywords = flexport_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flexport_scan,
};

int br_flexport_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flexport_fail(error, "invalid Flexport detector output");
    *out = NULL;
    if (!flexport_detector.state) {
        br_regex *pattern = NULL;
        /* DIRECT and case-sensitive. NO PrefixRegex, end boundary or delimiter. */
        if (br_regex_compile("\\b(shltm_[0-9a-zA-Z-_]{40})", &pattern, error) != 0) return -1;
        flexport_detector.state = pattern;
    }
    *out = &flexport_detector;
    return 0;
}
