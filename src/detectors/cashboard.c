/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cashboard/cashboard.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *username; } cashboard_patterns;

static int cashboard_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int cashboard_verify(const br_scan_ctx *ctx, br_slice key, br_slice username,
                             br_result *result, char **error)
{
    char *authorization = NULL;
    /* Username is unbounded. Encode every captured byte with the shared dynamic
     * helper; its positive as well as negative failures are fatal resources. */
    if (br_http_basic_auth(username, key, &authorization, NULL) != 0) {
        free(authorization);
        return cashboard_fail(error, "out of memory constructing Cashboard Basic authentication");
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.cashboardapp.com/account.xml",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 685,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the entire adapter/Do nonzero domain, including setup/allocation
     * failures that ABI1 cannot distinguish from Client.Do errors. No text IDs. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers successful response Close only until FromData returns.
     * Eager buffering and per-request ABI release remain lifecycle gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int cashboard_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cashboard_fail(error, "invalid Cashboard scan arguments");
    const cashboard_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->username)
        return cashboard_fail(error, "uninitialized Cashboard detector");
    size_t original_len = out->len;
    br_captures keys = {0}, usernames = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->username, input, &usernames, false, error);
    /* Independently collected usernames can be numeric key fragments or context
     * words. Do not filter them, deduplicate, consume pairs or break on success. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
            /* The fixed request is otherwise constructor-safe. Only known nil
             * context creation failures skip candidates, never Do failures. */
            if (verify && !ctx) continue;
            br_slice username = br_captures_at(&usernames, u);
            br_result result = {0};
            /* Both capture alphabets exclude whitespace: TrimSpace is a no-op. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", username, "username", (br_slice){0}) != 0)
                rc = cashboard_fail(error, "out of memory creating Cashboard result");
            else if (verify) rc = cashboard_verify(ctx, key, username, &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = cashboard_fail(error, "out of memory appending Cashboard result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&usernames);
    return rc == 0 ? 0 : -1;
}

static cashboard_patterns cashboard_compiled;
static const char *const cashboard_keywords[] = {"cashboard"};
static const br_detector cashboard_detector = {
    .type = 685, .version = 0, .name = "Cashboard", .custom_name = "",
    .description = "Cashboard is a financial management service. "
                   "Cashboard credentials can be used to access and manage financial data and accounts.",
    .keywords = cashboard_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &cashboard_compiled, .scan = cashboard_scan,
};

int br_cashboard_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cashboard_fail(error, "invalid Cashboard detector output");
    *out = NULL;
    if (!cashboard_compiled.key && br_regex_compile_prefixed(cashboard_keywords, 1,
        "\\b([0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3})\\b", &cashboard_compiled.key, error) != 0) return -1;
    if (!cashboard_compiled.username && br_regex_compile_prefixed(cashboard_keywords, 1,
        "\\b([0-9a-z]{1,})\\b", &cashboard_compiled.username, error) != 0) return -1;
    *out = &cashboard_detector;
    return 0;
}
