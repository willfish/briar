/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailerlite/mailerlite.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mailerlite_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's skip, not verification rejection. */
static bool mailerlite_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return false;
    const br_header headers[] = {{"X-Mailerlite-Apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.mailerlite.com/api/v2/campaigns",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the entire mixed preparation/Do error domain without inspecting
     * diagnostic text. This provider never calls the verification-error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Original header/key/URL storage survives this one
     * release per attempt; synthesized HTTP storage ends at send return. Source
     * scan-deferred Close scheduling is not reproduced by ABI1 release. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int mailerlite_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mailerlite_fail(error, "invalid or uninitialized Mailerlite scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace cannot change the ASCII capture. Keep occurrences and
         * duplicates, with the finding allocated before the nil-context skip. */
        if (key.len != 32)
            rc = mailerlite_fail(&owned_error, "invalid Mailerlite capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mailerlite_fail(&owned_error, "cannot create Mailerlite finding");
        if (rc == 0 && verify)
            keep = mailerlite_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = mailerlite_fail(&owned_error, "cannot append Mailerlite finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mailerlite_keywords[] = {"mailerlite"};
static br_detector mailerlite_detector = {
    .type = 228, .version = 0, .name = "Mailerlite", .custom_name = "",
    .description = "MailerLite is an email marketing service that allows users to create and manage email campaigns. MailerLite API keys can be used to access and modify email campaign data.",
    .keywords = mailerlite_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mailerlite_scan,
};

int br_mailerlite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mailerlite_fail(error, "invalid Mailerlite detector output");
    *out = NULL;
    if (!mailerlite_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(mailerlite_keywords, 1, "\\b([a-z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        mailerlite_detector.state = regex;
    }
    *out = &mailerlite_detector;
    return 0;
}
