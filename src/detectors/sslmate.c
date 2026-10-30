/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sslmate/sslmate.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { SM_ABORT = -1, SM_KEEP = 0, SM_DROP = 1 } sm_outcome;

static int sm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static sm_outcome sm_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return SM_DROP;
    if (strlen(key) != 36) return sm_fail(error, "unexpected SslMate key length"), SM_ABORT;
    /* Basic uses the raw key. It is not standard-base64 encoded. */
    char authorization[6 + 36 + 1];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, key, 37);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://sslmate.com/api/v2/certs/example.com?expand=current.crt",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return SM_KEEP;
}

static int sm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sm_fail(error, "invalid or uninitialized SslMate scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        sm_outcome outcome = SM_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = sm_fail(&owned_error, "cannot create SslMate result");
        else if (verify)
            outcome = sm_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == SM_ABORT) rc = -1;
        if (rc == 0 && outcome == SM_KEEP && br_results_push(out, &result) != 0)
            rc = sm_fail(&owned_error, "cannot append SslMate result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sm_keywords[] = {"sslmate"};
static br_detector sm_detector = {
    .type = 109, .version = 0, .name = "SslMate", .custom_name = "",
    .description = "SslMate is a service that helps manage and automate SSL certificates. SslMate API keys can be used to access and manage SSL certificates.",
    .keywords = sm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sm_scan,
};

int br_sslmate_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sm_fail(error, "invalid SslMate detector output");
    *out = NULL;
    if (br_key_pattern_init(&sm_detector, "\\b([a-zA-Z0-9]{36})\\b", error) != 0) return -1;
    *out = &sm_detector;
    return 0;
}
