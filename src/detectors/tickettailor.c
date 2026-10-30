/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tickettailor/tickettailor.go. */
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

static int set_error(br_result *result, const char *message, char **error)
{
    if (br_result_set_verification_error(result, message, NULL, 0) != 0)
        return fail(error, "cannot record TicketTailor verification error");
    return 0;
}

static int verify_tickettailor(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return set_error(result, "net/http: nil Context", error);
    char *authorization = NULL;
    br_slice username = {(const unsigned char *)key, strlen(key)};
    if (br_http_basic_auth(username, (br_slice){0}, &authorization, error) != 0)
        return fail(error, "cannot format TicketTailor authorization");
    unsigned char dedup[51];
    memcpy(dedup, "840:", 4);
    memcpy(dedup + 4, key, 47);
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.tickettailor.com/v1/events",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 840, .dedup_key = {dedup, sizeof(dedup)},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    int rc = 0;
    if (sent == 0 && response.status == 200) result->verified = true;
    else if (sent == 0 && response.status != 401 && response.status != 403) {
        char message[64];
        int formatted = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = fail(error, "cannot format TicketTailor status");
        else rc = set_error(result, message, error);
    }
    br_http_release(ctx, &response);
    free(authorization);
    return rc;
}

static int scan_tickettailor(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TicketTailor scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, true, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating TicketTailor result");
        else if (verify && verify_tickettailor(ctx, keys.items[i], &result, error) != 0)
            rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append TicketTailor result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const tickettailor_keywords[] = {"tickettailor"};
static br_detector tickettailor_detector = {
    .type = 840, .version = 0, .name = "Tickettailor", .custom_name = "",
    .description = "Tickettailor is an online ticketing platform that allows event organizers to sell tickets. Tickettailor API keys can be used to manage events, orders, and tickets programmatically.",
    .keywords = tickettailor_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_tickettailor,
};

int br_tickettailor_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TicketTailor detector output");
    *out = NULL;
    /* No trailing boundary: a longer hex run still captures the first 32. */
    if (br_key_pattern_init(&tickettailor_detector, "\\b(sk_[0-9]{4}_[0-9]{6}_[a-f0-9]{32})", error) != 0)
        return -1;
    *out = &tickettailor_detector;
    return 0;
}
