/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/raven/raven.go.
 * The implementation exists but is commented out of the default detector list. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { RV_ABORT = -1, RV_KEEP = 0, RV_DROP = 1 } rv_outcome;

static int rv_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

__attribute__((weak)) int br_raven_json_document(br_slice body, br_json **out, char **cause)
{
    return br_json_document(body, out, cause);
}

static rv_outcome rv_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    /* fmt.Sprintf runs while evaluating NewRequestWithContext arguments. */
    char url[96];
    int n = snprintf(url, sizeof(url),
                     "https://api.raventools.com/api?key=%s&method=profile_info&format=json", key);
    if (n < 0 || (size_t)n >= sizeof(url))
        return rv_fail(error, "cannot format Raven verification URL"), RV_ABORT;
    if (!ctx) return RV_DROP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    rv_outcome outcome = RV_KEEP;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* Transport failure still retains an unverified finding and sets nothing. */
    } else if (response.body_error) {
        /* ReadAll failure continues before Close and before the status check. */
        outcome = RV_DROP;
    } else if (response.status >= 200 && response.status < 300) {
        br_json *document = NULL;
        char *cause = NULL;
        int valid = br_raven_json_document(response.body, &document, &cause);
        if (valid != 0 && valid != 1) rc = rv_fail(error, "cannot validate Raven response JSON");
        else if (valid == 0) result->verified = true;
        json_object_put(document);
        free(cause);
    }
    br_http_release(ctx, &response);
    free(send_error);
    if (rc != 0) return RV_ABORT;
    return outcome;
}

static int rv_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return rv_fail(error, "invalid or uninitialized Raven scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        rv_outcome outcome = RV_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = rv_fail(&owned_error, "cannot create Raven result");
        else if (verify)
            outcome = rv_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == RV_ABORT) rc = -1;
        if (rc == 0 && outcome == RV_KEEP && br_results_push(out, &result) != 0)
            rc = rv_fail(&owned_error, "cannot append Raven result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rv_keywords[] = {"raven"};
static br_detector rv_detector = {
    .type = 330, .version = 0, .name = "Raven", .custom_name = "",
    .description = "Raven credentials can be used to access and manage your Raven account and services.",
    .keywords = rv_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = rv_scan,
};

int br_raven_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rv_fail(error, "invalid Raven detector output");
    *out = NULL;
    if (br_key_pattern_init(&rv_detector, "\\b([A-Z0-9-]{16})\\b", error) != 0) return -1;
    *out = &rv_detector;
    return 0;
}
