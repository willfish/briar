/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ramp/ramp.go.
 * RE2 [[:alnum:]] is ASCII; the classes below match that, not Unicode. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *key_re, *secret_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_ramp(const br_scan_ctx *ctx, const char *key, const char *secret,
                       br_result *result, char **error)
{
    /* url.Values.Encode sorts grant_type before scope and escapes the colon. */
    static const char body[] = "grant_type=client_credentials&scope=user%3Aread";
    if (!ctx) return 1;
    char *authorization = NULL;
    br_slice username = {(const unsigned char *)key, strlen(key)};
    br_slice password = {(const unsigned char *)secret, strlen(secret)};
    if (br_http_basic_auth(username, password, &authorization, error) != 0) return -1;
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/x-www-form-urlencoded"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.ramp.com/developer/v1/token",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int rc = 0;
    if (!sent && response.status >= 200 && response.status < 300) result->verified = true;
    else if (sent || response.status != 401) {
        char message[64];
        const char *cause = transport_error;
        if (!sent) {
            snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
            cause = message;
        }
        br_slice redact = {(const unsigned char *)key, strlen(key)};
        if (br_result_set_verification_error(result, cause, &redact, 1) != 0)
            rc = fail(error, "cannot set Ramp verification error");
    }
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc;
}

static int scan_ramp(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !secret_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Ramp scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(secret_re, input, &secrets, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        for (size_t j = 0; !rc && j < secrets.len; ++j) {
            br_result result = {0};
            int outcome = 0;
            /* TrimSpace cannot change these alphanumeric captures. */
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, i), "key",
                                      br_captures_at(&secrets, j), "secret",
                                      (br_slice){(const unsigned char *)":", 1}) != 0) {
                fail(&owned_error, "cannot create Ramp result");
                outcome = -1;
            } else if (verify)
                outcome = verify_ramp(ctx, keys.items[i], secrets.items[j], &result, &owned_error);
            if (outcome == 0 && br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append Ramp result");
                outcome = -1;
            }
            br_result_clear(&result);
            if (outcome < 0) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"ramp_"};
static br_detector ramp = {
    .type = 934, .version = 0, .name = "Ramp", .custom_name = "",
    .description = "Ramp provides financial services including expense management and corporate cards. Ramp credentials can be used to access and manage these financial services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_ramp,
};

int br_ramp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Ramp detector output");
    *out = NULL;
    if (!key_re && br_regex_compile("\\b(ramp_id_[A-Za-z0-9]{40})\\b", &key_re, error) != 0) return -1;
    if (!secret_re && br_regex_compile("\\b(ramp_sec_[A-Za-z0-9]{48})\\b", &secret_re, error) != 0) return -1;
    ramp.state = key_re;
    *out = &ramp;
    return 0;
}
