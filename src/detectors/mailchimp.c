/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailchimp/mailchimp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static int mailchimp_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int mailchimp_metadata(br_result *result, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data)
        return mailchimp_fail(error, "cannot create Mailchimp metadata");
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/mailchimp/");
    if (!guide) return mailchimp_fail(error, "cannot create Mailchimp rotation guide");
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return mailchimp_fail(error, "cannot add Mailchimp rotation guide");
    }
    return 0;
}

static int mailchimp_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            bool *keep, char **error)
{
    static const char prefix[] = "https://";
    static const char suffix[] = ".api.mailchimp.com/3.0/";
    char url[sizeof(prefix) - 1 + 4 + sizeof(suffix)];
    size_t datacenter_len = key.len - 33;
    /* Preserve exact usN/usNN bytes, including zeros. Finding and rotation
     * metadata precede this complete URL and the constructor's nil-context skip. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data + 33, datacenter_len);
    memcpy(url + sizeof(prefix) - 1 + datacenter_len, suffix, sizeof(suffix));
    if (!ctx) {
        *keep = false;
        return 0;
    }
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)"anystring", 9}, key,
                           &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {
        {"Authorization", authorization}, {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole mixed preparation/Do nonzero domain keeps a false finding.
     * Do not classify diagnostic text or call a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors are ignored. Provider URL/auth/headers/key survive one
     * release per attempt; ordinary synthesized request storage does not survive
     * send return. ABI1 release differs from source scan-deferred Close timing. */
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return 0;
}

static int mailchimp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mailchimp_fail(error, "invalid or uninitialized Mailchimp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 36 && key.len != 37)
            rc = mailchimp_fail(&owned_error, "invalid Mailchimp capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mailchimp_fail(&owned_error, "cannot create Mailchimp finding");
        if (rc == 0) rc = mailchimp_metadata(&result, &owned_error);
        if (rc == 0 && verify) rc = mailchimp_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = mailchimp_fail(&owned_error, "cannot append Mailchimp finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mailchimp_keywords[] = {"-us"};
static br_detector mailchimp_detector = {
    .type = 20, .version = 0, .name = "Mailchimp", .custom_name = "",
    .description = "Mailchimp is a marketing automation platform and email marketing service. Mailchimp API keys can be used to access and manage email campaigns, audience data, and other marketing resources.",
    .keywords = mailchimp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mailchimp_scan,
};

int br_mailchimp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mailchimp_fail(error, "invalid Mailchimp detector output");
    *out = NULL;
    if (!mailchimp_detector.state) {
        br_regex *regex = NULL;
        /* Enclose the whole source match for the existing capture collector;
         * there is no prefix, boundary, trim or case-folding policy. */
        if (br_regex_compile("([0-9a-f]{32}-us[0-9]{1,2})", &regex, error) != 0)
            return -1;
        mailchimp_detector.state = regex;
    }
    *out = &mailchimp_detector;
    return 0;
}
