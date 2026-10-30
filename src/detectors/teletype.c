/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/teletype/teletype.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int teletype_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool teletype_contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > body.len || !body.data) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int teletype_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return 1;
    char token[65];
    memcpy(token, key, 64);
    token[64] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Auth-Token", token},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.teletype.app/public/api/v1/messages",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int outcome = 0;
    /* A body read failure drops the candidate. Do errors stay unverified. */
    if (sent == 0 && response.body_error) outcome = 1;
    else if (sent == 0 && response.status >= 200 && response.status < 300)
        result->verified = !teletype_contains(response.body, "\"code\":401");
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int teletype_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return teletype_fail(error, "invalid or uninitialized Teletype scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        int outcome = 0;
        if (key.len != 64) rc = teletype_fail(&owned_error, "invalid Teletype capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = teletype_fail(&owned_error, "cannot create Teletype result");
        else if (verify) outcome = teletype_verify(ctx, keys.items[i], &result);
        if (rc == 0 && outcome == 0 && br_results_push(out, &result) != 0)
            rc = teletype_fail(&owned_error, "cannot append Teletype result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const teletype_keywords[] = {"teletype"};
static br_detector teletype_detector = {
    .type = 777, .version = 0, .name = "Teletype", .custom_name = "",
    .description = "Teletype is a messaging service. Teletype API keys can be used to access and send messages through the Teletype API.",
    .keywords = teletype_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = teletype_scan,
};

int br_teletype_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return teletype_fail(error, "invalid Teletype detector output");
    *out = NULL;
    if (br_key_pattern_init(&teletype_detector, "\\b([0-9a-zA-Z-]{64})\\b", error) != 0) return -1;
    *out = &teletype_detector;
    return 0;
}
