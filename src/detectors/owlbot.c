/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/owlbot/owlbot.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int owlbot_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int owlbot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return owlbot_fail(error, "invalid or uninitialized Owlbot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase-alphanumeric grammar. */
        if (key.len != 40 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = owlbot_fail(&owned_error, "cannot create Owlbot result");
        if (rc == 0 && verify) {
            /* Fixed-URL constructor failure (nil context) drops this candidate
             * before the Token header, send or release. */
            if (ctx) {
                char authorization[sizeof("Token ") + 40];
                memcpy(authorization, "Token ", 6);
                memcpy(authorization + 6, keys.items[i], 40);
                authorization[46] = '\0';
                const br_header headers[] = {{"Authorization", authorization}};
                const br_http_request request = {
                    .method = "GET", .url = "https://owlbot.info/api/v4/dictionary/security",
                    .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
                    .detector_type = detector->type,
                };
                br_http_response response = {0};
                char *send_error = NULL;
                if (br_http_send(ctx, &request, &response, &send_error) == 0)
                    result.verified = response.status >= 200 && response.status < 300;
                br_http_release(ctx, &response);
                free(send_error);
            } else {
                br_result_clear(&result);
                continue;
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = owlbot_fail(&owned_error, "cannot append Owlbot result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const owlbot_keywords[] = {"owlbot"};
static br_detector owlbot_detector = {
    .type = 357, .version = 0, .name = "Owlbot", .custom_name = "",
    .description = "Owlbot is an API service providing dictionary definitions, synonyms, and example sentences. Owlbot API keys can be used to access and retrieve this data.",
    .keywords = owlbot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = owlbot_scan,
};

int br_owlbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return owlbot_fail(error, "invalid Owlbot detector output");
    *out = NULL;
    if (br_key_pattern_init(&owlbot_detector, "\\b([a-z0-9]{40})\\b", error) != 0) return -1;
    *out = &owlbot_detector;
    return 0;
}
