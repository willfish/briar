/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/easyinsight/easyinsight.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } easyinsight_patterns;

static int easyinsight_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int easyinsight_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                              br_result *result, char **error)
{
    /* Constructor failure RETAINS the finding, BEFORE any Basic preparation. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return easyinsight_fail(error, "cannot set EasyInsight verification error");
        return 0;
    }
    char *authorization = NULL;
    /* Source SetBasicAuth uses ID as username, KEY as password, not Raw order.
     * One complete owned value is borrowed through BOTH send and release. */
    if (br_http_basic_auth(id, key, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://www.easy-insight.com/app/api/users.json",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* The whole shared setup/allocation/Do domain is an ordinary leaf cause.
     * Do not classify text, strip arbitrary wrappers or redact credentials. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = easyinsight_fail(error, "cannot format EasyInsight verification status");
        else cause = status_error;
    }
    /* Source calls its ZERO-redaction setter only for nonnil errors. An empty
     * non-NULL cause still counts; every nonzero setter result is scan-fatal.
     * Copy before release, never borrow transport storage into a finding. */
    if (rc == 0 && cause && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = easyinsight_fail(error, "cannot set EasyInsight verification error");
    /* Source drains/closes after status and ignores every body/read error.
     * Eager buffering/release, drain timing, private-client behavior, full
     * SANE/RE2 and global engine/output parity remain open. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int easyinsight_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return easyinsight_fail(error, "invalid or uninitialized EasyInsight scan");
    const easyinsight_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return easyinsight_fail(error, "uninitialized EasyInsight patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    /* Independent byte-original sets: provider names overlap but the generic
     * role keywords differ. Native first-occurrence order is a choice of the
     * source's unspecified map order. No trimming, local span cap or filtering. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            if (key.len == id.len && !memcmp(key.data, id.data, key.len)) continue;
            br_result result = {0};
            /* Fresh parts and RawV2=KEY+ID precede constructor/verification. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = easyinsight_fail(&owned_error, "cannot create EasyInsight result");
            if (rc == 0 && verify)
                rc = easyinsight_verify(ctx, key, id, &result, &owned_error);
            bool verified = result.verified;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = easyinsight_fail(&owned_error, "cannot append EasyInsight result");
            br_result_clear(&result);
            if (rc == 0 && verified) break; /* AFTER append; only this key's ID loop. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static easyinsight_patterns easyinsight_compiled;
static const char *const easyinsight_keywords[] = {"easyinsight", "easy-insight"};
static const br_detector easyinsight_detector = {
    .type = 282, .version = 0, .name = "EasyInsight", .custom_name = "",
    .description = "EasyInsight is a business intelligence tool that provides data visualization and reporting. EasyInsight API keys can be used to access and manage data within the platform.",
    .keywords = easyinsight_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &easyinsight_compiled, .scan = easyinsight_scan,
};

int br_easyinsight_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return easyinsight_fail(error, "invalid EasyInsight detector output");
    *out = NULL;
    static const char *const key_keywords[] = {"easyinsight", "easy-insight", "key"};
    static const char *const id_keywords[] = {"easyinsight", "easy-insight", "id"};
    /* The source comment says the regexes are the same, but their PREFIX SETS
     * are not. Dispatch also deliberately omits the generic role keywords. */
    if (!easyinsight_compiled.key && br_regex_compile_prefixed(key_keywords, 3,
            "\\b([0-9a-zA-Z]{20})\\b", &easyinsight_compiled.key, error) != 0) return -1;
    if (!easyinsight_compiled.id && br_regex_compile_prefixed(id_keywords, 3,
            "\\b([a-zA-Z0-9]{20})\\b", &easyinsight_compiled.id, error) != 0) return -1;
    *out = &easyinsight_detector;
    return 0;
}
