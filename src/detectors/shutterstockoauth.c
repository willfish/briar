/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shutterstockoauth/shutterstockoauth.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { SS_ABORT = -1, SS_KEEP = 0, SS_DROP = 1 } ss_outcome;

static int ss_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static ss_outcome ss_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return SS_DROP;
    if (strlen(key) != 391) return ss_fail(error, "unexpected ShutterstockOAuth key length"), SS_ABORT;
    char authorization[7 + 391 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 392);
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.shutterstock.com/v2/user",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return SS_KEEP;
}

static int ss_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ss_fail(error, "invalid or uninitialized ShutterstockOAuth scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        ss_outcome outcome = SS_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = ss_fail(&owned_error, "cannot create ShutterstockOAuth result");
        else if (verify)
            outcome = ss_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == SS_ABORT) rc = -1;
        if (rc == 0 && outcome == SS_KEEP && br_results_push(out, &result) != 0)
            rc = ss_fail(&owned_error, "cannot append ShutterstockOAuth result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ss_keywords[] = {"shutterstock"};
static br_detector ss_detector = {
    .type = 519, .version = 0, .name = "ShutterstockOAuth", .custom_name = "",
    .description = "A service for saving and accessing photos. OAuth credentials can be used to potentially access user photos.",
    .keywords = ss_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ss_scan,
};

int br_shutterstockoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ss_fail(error, "invalid ShutterstockOAuth detector output");
    *out = NULL;
    if (br_key_pattern_init(&ss_detector, "\\b(v2/[0-9A-Za-z]{388})\\b", error) != 0) return -1;
    *out = &ss_detector;
    return 0;
}
