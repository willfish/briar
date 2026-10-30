/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tiingo/tiingo.go. */
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

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

/* Only a 2xx response is verified. Do errors and other statuses are ignored.
 * A nil context drops the candidate before append. */
static int verify_tiingo(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx) return 1;
    const char *key = (const char *)secret.data;
    char *auth = malloc(6 + strlen(key) + 1);
    if (!auth) return fail(error, "cannot format Tiingo authorization");
    memcpy(auth, "Token ", 6);
    memcpy(auth + 6, key, strlen(key) + 1);
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.tiingo.com/tiingo/fundamentals/definitions",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 421,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(send_error);
    free(auth);
    return rc;
}

static int scan_tiingo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Tiingo scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create Tiingo finding");
        } else if (verify) {
            int status = verify_tiingo(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Tiingo finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"tiingo"};
static br_detector tiingo = {
    .type = 421, .version = 0, .name = "Tiingo", .custom_name = "",
    .description = "Tiingo is a financial data platform that provides access to various financial data and APIs. Tiingo API keys can be used to access and retrieve financial data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_tiingo,
};

int br_tiingo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Tiingo detector output");
    *out = NULL;
    if (br_key_pattern_init(&tiingo, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &tiingo;
    return 0;
}
