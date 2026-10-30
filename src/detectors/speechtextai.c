/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/speechtextai/speechtextai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_speechtext(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (key.len != 32) return fail(error, "invalid SpeechTextAI capture");
    static const char prefix[] = "https://api.speechtext.ai/recognize?key=";
    static const char suffix[] = "&language=en-US&punctuation=true&format=m4a";
    char url[sizeof(prefix) + 32 + sizeof(suffix)];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
    /* Header.Add runs before the constructor error check, so a nil request panics. */
    if (!ctx) return fail(error, "runtime error: invalid memory address or nil pointer dereference");
    const br_header headers[] = {{"Content-Type", "application/octet-stream"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_speechtext(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SpeechTextAI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create SpeechTextAI result");
        else if (verify) rc = verify_speechtext(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append SpeechTextAI result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"speechtext"};
static br_detector detector = {
    .type = 849, .name = "SpeechTextAI", .custom_name = "",
    .description = "SpeechTextAI is a service that provides speech-to-text conversion. The API key can be used to access and utilize the speech-to-text services offered by SpeechTextAI.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_speechtext,
};

int br_speechtextai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SpeechTextAI detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{32})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
