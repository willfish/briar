/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/langsmith/langsmith.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Nil cause is a checked no-op. Nonzero, including +1, is fatal before append. */
static int set_cause(br_result *result, br_slice key, const char *cause, char **error)
{
    br_slice secret = key;
    if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
        return fail(error, "cannot record LangSmith verification error");
    return 0;
}

static int verify_langsmith(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* A nil context is an unverified finding, not a dropped candidate. */
    if (!ctx) return set_cause(result, key, "net/http: nil Context", error);
    char api_key[52];
    _Static_assert(sizeof(api_key) == 52, "LangSmith key is 51 bytes plus NUL");
    memcpy(api_key, key.data, 51);
    api_key[51] = '\0';
    /* Go canonicalizes the source spelling X-API-Key to X-Api-Key. */
    const br_header headers[] = {{"X-Api-Key", api_key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.smith.langchain.com/api/v1/api-key",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    /* Status is read before release clears it. The body and body_error are ignored. */
    int status = response.status;
    const char *cause = NULL;
    char status_cause[64];
    int rc = 0;
    /* Source builds this error before the deferred close. A negative return and
     * a result that does not fit are fatal. A missing send cause stays NULL. */
    if (sent != 0)
        cause = send_error;
    else if (status != 200 && status != 401 && status != 403) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = fail(error, "cannot format LangSmith verification status");
        else cause = status_cause;
    }
    /* Release once while the original key bytes are still alive. */
    br_http_release(ctx, &response);
    if (rc != 0) {
        free(send_error);
        return rc; /* No verdict and no setter. The scan rolls this invocation back. */
    }
    if (sent == 0 && status == 200) result->verified = true;
    rc = set_cause(result, key, cause, error);
    free(send_error);
    return rc;
}

static int scan_langsmith(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized LangSmith scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* First exact occurrence only. Go map order is unspecified; first-seen is
     * the chosen order. The grammar is unprefixed, so this is not PrefixRegex. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create LangSmith finding");
            rc = -1;
        } else if (verify && verify_langsmith(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append LangSmith finding");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"lsv2_pt_", "lsv2_sk_"};
static br_detector langsmith = {
    .type = 1028,
    .version = 0,
    .name = "LangSmith",
    .custom_name = "",
    .description = "LangSmith is a unified observability & evals platform where teams can debug, test, and monitor AI app performance \xe2\x80\x94 whether building with LangChain or not",
    .keywords = keywords,
    .nkeywords = 2,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_langsmith,
};

int br_langsmith_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid LangSmith detector output");
    *out = NULL;
    if (!langsmith.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\\b", &regex, error) != 0)
            return -1;
        langsmith.state = regex;
    }
    *out = &langsmith;
    return 0;
}
