/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailjetsms/mailjetsms.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mailjetsms_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void mailjetsms_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[40];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 32);
    authorization[39] = '\0';
    const br_header headers[] = {
        {"Accept", "application/vnd.mailjetsms+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.mailjet.com/v4/sms",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses the WHOLE mixed preparation/Do error domain without
     * a setter. All 2xx verify, regardless of response bodies/read errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider header/auth/key/URL storage survives exactly one release per
     * attempt. Synthesized prepared headers/UA end at ordinary send return. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int mailjetsms_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mailjetsms_fail(error, "invalid or uninitialized MailJetSMS scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace cannot alter this ASCII-alphanumeric grammar. Preserve
         * original key case, occurrence order, duplicates and key-only fields. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = mailjetsms_fail(&owned_error, "cannot create MailJetSMS finding");
        if (rc == 0 && verify) {
            /* The complete finding precedes the constructor's nil-context
             * skip; fixed Bearer/header assembly is reached only afterward. */
            if (!ctx) { br_result_clear(&result); continue; }
            mailjetsms_verify(ctx, keys.items[i], &result);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mailjetsms_fail(&owned_error, "cannot append MailJetSMS finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        mailjetsms_fail(&owned_error, "cannot collect MailJetSMS keys");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mailjetsms_keywords[] = {"mailjet"};
static br_detector mailjetsms_detector = {
    .type = 106, .version = 0, .name = "MailJetSMS", .custom_name = "",
    .description = "Mailjet is a cloud-based email service provider. Mailjet API keys can be used to send SMS messages and manage email campaigns.",
    .keywords = mailjetsms_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mailjetsms_scan,
};

int br_mailjetsms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mailjetsms_fail(error, "invalid MailJetSMS detector output");
    *out = NULL;
    if (!mailjetsms_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(mailjetsms_keywords, 1, "\\b([A-Za-z0-9]{32})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        mailjetsms_detector.state = pattern;
    }
    *out = &mailjetsms_detector;
    return 0;
}
