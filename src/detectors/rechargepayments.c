/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rechargepayments/rechargepayments.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *newer, *sha224, *md5;
} recharge_patterns;

typedef enum { RECHARGE_ABORT = -1, RECHARGE_KEEP = 0, RECHARGE_SKIP = 1 } recharge_outcome;

static int recharge_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static recharge_outcome recharge_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                        char **error)
{
    char token[80];
    if (key.len >= sizeof(token)) {
        recharge_fail(error, "cannot format RechargePayments token");
        return RECHARGE_ABORT;
    }
    memcpy(token, key.data, key.len);
    token[key.len] = '\0';
    if (!ctx) return RECHARGE_SKIP;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Recharge-Access-Token", token},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.rechargeapps.com/token_information",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Only StatusOK verifies. Do errors and the unused body do not set an error.
     * A fresh SaneHttpClient is created per attempt; timeout stays 5s. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status == 200;
    br_http_release(ctx, &response);
    free(transport_error);
    return RECHARGE_KEEP;
}

static int recharge_emit(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         const br_captures *keys, br_results *out, char **owned_error)
{
    for (size_t i = 0; i < keys->len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(keys, i);
        recharge_outcome outcome = RECHARGE_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            recharge_fail(owned_error, "cannot create RechargePayments result");
            outcome = RECHARGE_ABORT;
        } else if (verify)
            outcome = recharge_verify(ctx, key, &result, owned_error);
        if (outcome == RECHARGE_ABORT) {
            br_result_clear(&result);
            return -1;
        }
        if (outcome == RECHARGE_KEEP && br_results_push(out, &result) != 0) {
            br_result_clear(&result);
            recharge_fail(owned_error, "cannot append RechargePayments result");
            return -1;
        }
        br_result_clear(&result);
    }
    return 0;
}

static int recharge_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const recharge_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->newer || !patterns->sha224 || !patterns->md5 ||
        !out || (!input.data && input.len))
        return recharge_fail(error, "invalid or uninitialized RechargePayments scan");
    size_t original_len = out->len;
    br_captures newer = {0}, sha = {0}, md5 = {0};
    char *owned_error = NULL;
    /* The Go map order is unspecified. Literal source order is newer, SHA-224, MD5.
     * Each pattern keeps every occurrence, including duplicates. */
    int rc = br_captures_find(patterns->newer, input, &newer, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->sha224, input, &sha, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->md5, input, &md5, false, &owned_error);
    if (rc == 0) rc = recharge_emit(detector, ctx, verify, &newer, out, &owned_error);
    if (rc == 0) rc = recharge_emit(detector, ctx, verify, &sha, out, &owned_error);
    if (rc == 0) rc = recharge_emit(detector, ctx, verify, &md5, out, &owned_error);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&newer);
    br_captures_clear(&sha);
    br_captures_clear(&md5);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const recharge_keywords[] = {
    "sk_1x1", "sk_1x3", "sk_2x1", "sk_2x2", "sk_3x3", "sk_5x3", "sk_10x3",
    "sk_test_1x1", "sk_test_1x3", "sk_test_2x1", "sk_test_2x2", "sk_test_3x3",
    "sk_test_5x3", "sk_test_10x3", "X-Recharge-Access-Token",
};
static recharge_patterns recharge_state;
static br_detector recharge_detector = {
    .type = 818, .version = 0, .name = "RechargePayments", .custom_name = "",
    .description = "Recharge is a subscription payment solution. "
                   "Recharge API keys can be used to access and manage subscription data and transactions.",
    .keywords = recharge_keywords, .nkeywords = 15,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = recharge_scan,
};

int br_rechargepayments_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return recharge_fail(error, "invalid RechargePayments detector output");
    *out = NULL;
    /* Inner group is non-capturing so group 1 is the full FindAllString match. */
    if (!recharge_state.newer &&
        br_regex_compile("\\b(sk(?:_test)?_(?:1|2|3|5|10)x[123]_[0-9a-fA-F]{64})\\b",
                         &recharge_state.newer, error) != 0)
        return -1;
    if (!recharge_state.sha224 &&
        br_regex_compile("\\b([0-9a-fA-F]{56})\\b", &recharge_state.sha224, error) != 0)
        return -1;
    if (!recharge_state.md5 &&
        br_regex_compile("\\b([0-9a-fA-F]{32})\\b", &recharge_state.md5, error) != 0)
        return -1;
    recharge_detector.state = &recharge_state;
    *out = &recharge_detector;
    return 0;
}
