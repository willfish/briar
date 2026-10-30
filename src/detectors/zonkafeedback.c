/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zonkafeedback/zonkafeedback.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_zonka(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    br_slice redact = {(const unsigned char *)key, strlen(key)};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &redact, 1) == 0
            ? 0 : fail(error, "cannot set ZonkaFeedback verification error");
    const br_header headers[] = {{"Z-API-TOKEN", key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://app-us1.zonkafeedback.com/responses?page=1&limit=25&startDate=2020-05-02&endDate=2020-05-09",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    const char *cause = NULL;
    char message[64];
    int rc = 0;
    if (sent) cause = transport_error;
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        cause = message;
    }
    if (br_result_set_verification_error(result, cause, &redact, 1) != 0)
        rc = fail(error, "cannot set ZonkaFeedback verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_zonka(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ZonkaFeedback scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            fail(&owned_error, "cannot create ZonkaFeedback result");
            outcome = -1;
        } else if (verify && verify_zonka(ctx, keys.items[i], &result, &owned_error) != 0)
            outcome = -1;
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append ZonkaFeedback result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"zonka"};
static br_detector zonka = {
    .type = 236, .version = 0, .name = "ZonkaFeedback", .custom_name = "",
    .description = "ZonkaFeedback is a platform for collecting and analyzing customer feedback. The API token can be used to access and manage feedback data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_zonka,
};

int br_zonkafeedback_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ZonkaFeedback detector output");
    *out = NULL;
    if (!zonka.state && br_key_pattern_init(&zonka, "\\b([A-Za-z0-9]{36})\\b", error) != 0) return -1;
    *out = &zonka;
    return 0;
}
