/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/skybiometry/skybiometry.go. */
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

static int set_error(br_result *result, const char *message, char **error)
{
    if (br_result_set_verification_error(result, message, NULL, 0) != 0)
        return fail(error, "cannot record SkyBiometry verification error");
    return 0;
}

static int verify_skybiometry(const br_scan_ctx *ctx, const char *key, const char *secret,
                              br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://api.skybiometry.com/fc/account/authenticate?api_key=%s&api_secret=%s",
                     key, secret);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format SkyBiometry URL");
    if (!ctx) return set_error(result, "net/http: nil Context", error);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 520,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) rc = set_error(result, send_error, error);
    else if (response.status == 200) result->verified = true;
    else if (response.status != 400 && response.status != 401) {
        char message[64];
        int formatted = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = fail(error, "cannot format SkyBiometry status");
        else rc = set_error(result, message, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_skybiometry(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SkyBiometry scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    /* Both patterns are identical. Go map iteration is unordered; this keeps
     * first-seen order and still skips a key equal to its secret. */
    br_captures keys = {0}, secrets = {0};
    int rc = br_captures_find(patterns[0], input, &keys, true, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &secrets, true, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < secrets.len; ++j) {
            if (!strcmp(keys.items[i], secrets.items[j])) continue;
            br_result result = {0};
            /* Raw is the API secret. The single part is also named key. */
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&secrets, j), "key") != 0)
                rc = fail(error, "out of memory creating SkyBiometry result");
            else if (verify && verify_skybiometry(ctx, keys.items[i], secrets.items[j], &result, error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append SkyBiometry result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    return rc == 0 ? 0 : -1;
}

static const char *const skybiometry_keywords[] = {"skybiometry"};
static br_regex *skybiometry_patterns[2];
static br_detector skybiometry_detector = {
    .type = 520, .version = 0, .name = "SkyBiometry", .custom_name = "",
    .description = "SkyBiometry is a facial recognition service. SkyBiometry API keys can be used to access and utilize their facial recognition API.",
    .keywords = skybiometry_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = skybiometry_patterns, .scan = scan_skybiometry,
};

int br_skybiometry_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SkyBiometry detector output");
    *out = NULL;
    if (!skybiometry_patterns[0] &&
        br_regex_compile_prefixed(skybiometry_keywords, 1, "\\b([0-9a-z]{25,26})\\b",
                                  &skybiometry_patterns[0], error) != 0)
        return -1;
    if (!skybiometry_patterns[1] &&
        br_regex_compile_prefixed(skybiometry_keywords, 1, "\\b([0-9a-z]{25,26})\\b",
                                  &skybiometry_patterns[1], error) != 0)
        return -1;
    *out = &skybiometry_detector;
    return 0;
}
