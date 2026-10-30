/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/smooch/smooch.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } smooch_patterns;
typedef enum { SMOOCH_ABORT = -1, SMOOCH_KEEP = 0, SMOOCH_DROP = 1 } smooch_outcome;

static int smooch_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static smooch_outcome smooch_verify(const br_scan_ctx *ctx, const char *key, const char *secret,
                                    br_result *result, char **error)
{
    if (strlen(key) != 28 || strlen(secret) != 86)
        return smooch_fail(error, "unexpected Smooch credential length"), SMOOCH_ABORT;
    unsigned char plain[115], encoded[157];
    memcpy(plain, key, 28);
    plain[28] = ':';
    memcpy(plain + 29, secret, 86);
    /* EncodeToString is evaluated before NewRequestWithContext. */
    if (EVP_EncodeBlock(encoded, plain, 115) != 156)
        return smooch_fail(error, "Smooch Base64 encoding failed"), SMOOCH_ABORT;
    if (!ctx) return SMOOCH_DROP;
    char authorization[163];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, encoded, 157);
    const br_header headers[] = {
        {"Accept", "application/vnd.smooch+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.smooch.io/v2/apps",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return SMOOCH_KEEP;
}

static int smooch_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return smooch_fail(error, "invalid or uninitialized Smooch scan");
    const smooch_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            smooch_outcome outcome = SMOOCH_KEEP;
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                secrets.items[s], "secret") != 0)
                rc = smooch_fail(&owned_error, "cannot create Smooch result");
            else if (verify)
                outcome = smooch_verify(ctx, keys.items[k], secrets.items[s], &result, &owned_error);
            if (rc == 0 && outcome == SMOOCH_ABORT) rc = -1;
            if (rc == 0 && outcome == SMOOCH_KEEP && br_results_push(out, &result) != 0)
                rc = smooch_fail(&owned_error, "cannot append Smooch result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const smooch_keywords[] = {"smooch"};
static smooch_patterns smooch_state;
static br_detector smooch_detector = {
    .type = 608, .version = 0, .name = "Smooch", .custom_name = "",
    .description = "Smooch is a messaging platform that allows businesses to communicate with their customers across various messaging channels. Smooch API keys can be used to access and manage these communications.",
    .keywords = smooch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = smooch_scan, .state = &smooch_state,
};

int br_smooch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return smooch_fail(error, "invalid Smooch detector output");
    *out = NULL;
    if (!smooch_state.key &&
        br_regex_compile_prefixed(smooch_keywords, 1, "\\b(act_[0-9a-z]{24})\\b",
                                  &smooch_state.key, error) != 0)
        return -1;
    if (!smooch_state.secret &&
        br_regex_compile_prefixed(smooch_keywords, 1, "\\b([0-9a-zA-Z_-]{86})\\b",
                                  &smooch_state.secret, error) != 0)
        return -1;
    *out = &smooch_detector;
    return 0;
}
