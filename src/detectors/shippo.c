/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shippo/shippo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.goshippo.com/shippo-accounts?page=1&results=1";

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

static int verify_shippo(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    if (key.len > 80) return -1;
    char authorization[96];
    memcpy(authorization, "ShippoToken ", 12);
    memcpy(authorization + 12, key.data, key.len);
    authorization[12 + key.len] = '\0';
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
    else if (response.status != 401 && response.status != 403) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* The source sets the error before assigning Verified. */
    int rc = set_cause(result, cause);
    if (!rc) result->verified = verified;
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_shippo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shippo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len < 12 || br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Shippo result");
        else {
            char redacted[16];
            memcpy(redacted, key.data, 12);
            memcpy(redacted + 12, "...", 4);
            result.redacted = strdup(redacted);
            if (!result.redacted) rc = fail(&owned_error, "cannot create Shippo result");
        }
        if (!rc && verify && verify_shippo(ctx, key, &result))
            rc = fail(&owned_error, "cannot verify Shippo candidate");
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append Shippo result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"shippo_live_", "shippo_test_"};
static br_detector detector = {
    .type = 1060, .name = "Shippo", .custom_name = "",
    .description = "Shippo is a shipping API platform. Shippo live API tokens can be used to authenticate API requests and manage shipping operations.",
    .keywords = keywords, .nkeywords = 2, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_shippo,
};

int br_shippo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shippo detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile("\\b(shippo_(live|test)_[a-f0-9]{40})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
