/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/qubole/qubole.go. */
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

/* Constant URL and NoBody. Constructor failure is returned and kept.
 * Release covers the ignored drain and close and precedes the caller setter. */
static int verify_qubole(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0
            ? 0 : fail(error, "cannot set Qubole verification error");
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
        {"X-AUTH-TOKEN", (const char *)secret.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://us.qubole.com/api/v1.2/account",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 577,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error; /* Missing Do cause stays NULL. Do not invent one. */
    } else if (response.status == 200) {
        verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format Qubole status");
        else cause = status_error;
    }
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
            rc = fail(error, "cannot set Qubole verification error");
    }
    free(send_error);
    return rc;
}

static int scan_qubole(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Qubole scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* Match order, including duplicates. TrimSpace cannot change this capture. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
            rc = fail(&owned, "cannot create Qubole finding");
        if (!rc && verify) rc = verify_qubole(ctx, secret, &result, &owned);
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Qubole finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"qubole"};
static br_detector qubole = {
    .type = 577, .version = 0, .name = "Qubole", .custom_name = "",
    .description = "Qubole is a cloud-based data platform that provides data processing, management, and analytics services. Qubole API keys can be used to access and manage data workflows and resources.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_qubole,
};

int br_qubole_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Qubole detector output");
    *out = NULL;
    if (br_key_pattern_init(&qubole, "\\b([0-9a-z]{64})\\b", error) != 0) return -1;
    *out = &qubole;
    return 0;
}
