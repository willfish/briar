/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sendinbluev2/sendinbluev2.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int sendinbluev2_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sendinbluev2_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sendinbluev2_fail(error, "invalid or uninitialized SendinBlueV2 scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 89 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = sendinbluev2_fail(&owned_error, "cannot create SendinBlueV2 result");
        if (rc == 0 && verify) {
            static const char url[] = "https://api.sendinblue.com/v3/account";
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_header headers[] = {{"api-key", (const char *)key.data}};
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 1,
                .profile = BR_HTTP_SANE, .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = sendinbluev2_fail(&owned_error, "cannot append SendinBlueV2 result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sendinbluev2_keywords[] = {"xkeysib"};
static br_regex *sendinbluev2_pattern;
static br_detector sendinbluev2_detector = {
    .type = 86, .version = 0, .name = "SendinBlueV2", .custom_name = "",
    .description = "SendinBlue is a cloud-based marketing communication software. SendinBlue API keys can be used to access and modify marketing campaigns and contact data.",
    .keywords = sendinbluev2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sendinbluev2_scan,
};

int br_sendinbluev2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sendinbluev2_fail(error, "invalid SendinBlueV2 detector output");
    *out = NULL;
    /* The keyword is a dispatch hint only; the source pattern is unprefixed. */
    if (!sendinbluev2_pattern && br_regex_compile("\\b(xkeysib\\-[A-Za-z0-9_-]{81})\\b", &sendinbluev2_pattern, error) != 0)
        return -1;
    sendinbluev2_detector.state = sendinbluev2_pattern;
    *out = &sendinbluev2_detector;
    return 0;
}
