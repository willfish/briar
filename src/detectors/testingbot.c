/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/testingbot/testingbot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char testingbot_url[] = "https://api.testingbot.com/v1/user";

static int testingbot_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int testingbot_verify(const br_scan_ctx *ctx, br_slice id, br_slice key,
                             br_result *result, char **error)
{
    if (id.len != 32 || key.len != 32) return testingbot_fail(error, "invalid TestingBot capture");
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &key, 1)
            ? testingbot_fail(error, "cannot set TestingBot verification error") : 0;
    char *authorization = NULL;
    if (br_http_basic_auth(id, key, &authorization, error) != 0) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = testingbot_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = testingbot_fail(error, "cannot format TestingBot status");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = testingbot_fail(error, "cannot set TestingBot verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc;
}

static int testingbot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return testingbot_fail(error, "invalid or uninitialized TestingBot scan");
    size_t original_len = out->len;
    br_captures ids = {0};
    char *owned_error = NULL;
    /* Both upstream patterns are identical, so one unique scan is both maps.
     * First-seen order replaces Go's random map iteration. Equal pairs are skipped. */
    int rc = br_captures_find(detector->state, input, &ids, true, &owned_error);
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t k = 0; !rc && k < ids.len; ++k) {
            if (i == k) continue;
            br_slice id = br_captures_at(&ids, i);
            br_slice key = br_captures_at(&ids, k);
            if (id.len == key.len && !memcmp(id.data, key.data, id.len)) continue;
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = testingbot_fail(&owned_error, "cannot create TestingBot result");
            else if (verify && testingbot_verify(ctx, id, key, &result, &owned_error) != 0)
                rc = -1;
            else if (br_results_push(out, &result) != 0)
                rc = testingbot_fail(&owned_error, "cannot append TestingBot result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const testingbot_keywords[] = {"testingbot"};
static br_detector testingbot_detector = {
    .type = 759, .version = 0, .name = "TestingBot", .custom_name = "",
    .description = "TestingBot provides cross-browser testing services. TestingBot credentials can be used to automate tests on various browsers and devices.",
    .keywords = testingbot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = testingbot_scan,
};

int br_testingbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return testingbot_fail(error, "invalid TestingBot detector output");
    *out = NULL;
    if (br_key_pattern_init(&testingbot_detector, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &testingbot_detector;
    return 0;
}
