/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailboxlayer/mailboxlayer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mailboxlayer_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int mailboxlayer_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                               bool *keep, char **error)
{
    static const char prefix[] = "https://apilayer.net/api/check?access_key=";
    static const char suffix[] = "&email=support@email.com";
    char url[sizeof(prefix) - 1 + 32 + sizeof(suffix)];
    /* The fixed-length ASCII capture permits a bounded literal concatenation.
     * Construct the finding and full URL before the nil-context constructor skip. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
    if (!ctx) {
        *keep = false;
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* The whole mixed preparation/Do error domain retains a false finding and
     * must not inspect a populated response. No branch calls an error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error != NULL) {
            /* ReadAll errors drop even completed matching bytes, at any status. */
            *keep = false;
        } else if (!response.body.data && response.body.len) {
            rc = mailboxlayer_fail(error, "invalid Mailboxlayer response body slice");
        } else {
            static const unsigned char email[] = "email";
            static const unsigned char restricted[] =
                "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
            /* Status is deliberately never consulted. Match binary bytes, not JSON. */
            result->verified = br_slice_find(response.body,
                (br_slice){email, sizeof(email) - 1}, 0) != SIZE_MAX ||
                br_slice_find(response.body,
                    (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Original URL/key/request survive one release per attempted send, including
     * preparation failures. Synthesized request/UA storage ends at send return.
     * ABI1 release-before-publication differs from source scan-deferred Close. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int mailboxlayer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mailboxlayer_fail(error, "invalid or uninitialized Mailboxlayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace is a no-op for this grammar; preserve occurrences/duplicates. */
        if (key.len != 32)
            rc = mailboxlayer_fail(&owned_error, "invalid Mailboxlayer capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = mailboxlayer_fail(&owned_error, "cannot create Mailboxlayer finding");
        if (rc == 0 && verify) rc = mailboxlayer_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = mailboxlayer_fail(&owned_error, "cannot append Mailboxlayer finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mailboxlayer_keywords[] = {"mailboxlayer"};
static br_detector mailboxlayer_detector = {
    .type = 145, .version = 0, .name = "Mailboxlayer", .custom_name = "",
    .description = "Mailboxlayer is an email validation and verification service. Mailboxlayer API keys can be used to validate and verify email addresses.",
    .keywords = mailboxlayer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mailboxlayer_scan,
};

int br_mailboxlayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mailboxlayer_fail(error, "invalid Mailboxlayer detector output");
    *out = NULL;
    if (!mailboxlayer_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(mailboxlayer_keywords, 1, "\\b([a-z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        mailboxlayer_detector.state = regex;
    }
    *out = &mailboxlayer_detector;
    return 0;
}
