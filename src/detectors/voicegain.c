/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/voicegain/voicegain.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char voicegain_url[] = "https://api.voicegain.ai/v1/sa/config";

static int voicegain_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int voicegain_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            bool *keep, char **error)
{
    *keep = false;
    if (key.len != 191) return voicegain_fail(error, "invalid Voicegain capture");
    if (!ctx) return 0;
    char authorization[7 + 191 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 191);
    authorization[198] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = voicegain_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int voicegain_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return voicegain_fail(error, "invalid or uninitialized Voicegain scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = voicegain_fail(&owned_error, "cannot create Voicegain result");
        else if (verify && voicegain_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        else if (keep && br_results_push(out, &result) != 0)
            rc = voicegain_fail(&owned_error, "cannot append Voicegain result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const voicegain_keywords[] = {"voicegain"};
static br_detector voicegain_detector = {
    .type = 417, .version = 0, .name = "Voicegain", .custom_name = "",
    .description = "Voicegain is a speech recognition and natural language processing service. Voicegain API keys can be used to access and manage Voicegain services and data.",
    .keywords = voicegain_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = voicegain_scan,
};

int br_voicegain_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return voicegain_fail(error, "invalid Voicegain detector output");
    *out = NULL;
    /* The two dots are unescaped, matching the upstream pattern exactly. */
    if (br_key_pattern_init(&voicegain_detector,
            "\\b(ey[0-9a-zA-Z_-]{34}.ey[0-9a-zA-Z_-]{108}.[0-9a-zA-Z_-]{43})\\b", error) != 0)
        return -1;
    *out = &voicegain_detector;
    return 0;
}
