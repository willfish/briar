/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kickbox/kickbox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int kickbox_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int assemble_url(br_slice key, char **url_out)
{
    /* The leading class is unbounded. Concatenate the raw key; do not encode it. */
    static const char prefix[] = "https://api.kickbox.com/v2/verify?email=kickbox@example.com&apikey=";
    if (!url_out || (!key.data && key.len) || key.len > SIZE_MAX - sizeof(prefix)) return -1;
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return 1;
    memcpy(url, prefix, sizeof(prefix) - 1);
    if (key.len) memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    *url_out = url;
    return 0;
}

static int send_kickbox(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies. Other statuses, the whole mixed send domain, and
     * body_error stay unverified. Never call the verification-error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_kickbox(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return kickbox_fail(error, "invalid or uninitialized Kickbox scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* FindAll runs before a constructor drop, including a nil context.
     * Any nonzero, including +1, is fatal before that drop. */
    int capture_rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    int rc = capture_rc == 0 ? 0 : -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        char *url = NULL;
        int finding_rc = br_finding_key_bytes(&result, detector->type, key, "key");
        int url_rc = finding_rc == 0 && verify ? assemble_url(key, &url) : 0;
        if (finding_rc != 0)
            rc = kickbox_fail(&owned_error, "out of memory creating detector result");
        else if (url_rc != 0)
            rc = kickbox_fail(&owned_error, "out of memory allocating Kickbox URL");
        else if (verify && !ctx) {
            /* NewRequestWithContext(nil) drops only this candidate. No send or release. */
            free(url);
            br_result_clear(&result);
            continue;
        } else if (verify && send_kickbox(ctx, url, &result) != 0)
            rc = kickbox_fail(&owned_error, "cannot verify Kickbox candidate");
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = kickbox_fail(&owned_error, "out of memory appending detector result");
        free(url);
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const kickbox_keywords[] = {"kickbox"};
static br_detector kickbox_detector = {
    .type = 573, .version = 0, .name = "Kickbox", .custom_name = "",
    .description = "Kickbox is an email verification service that allows users to verify email addresses in real-time. Kickbox API keys can be used to access and utilize the email verification services provided by Kickbox.",
    .keywords = kickbox_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_kickbox,
};

int br_kickbox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return kickbox_fail(error, "invalid Kickbox detector output");
    *out = NULL;
    if (br_key_pattern_init(&kickbox_detector, "\\b([a-zA-Z0-9_]+[a-zA-Z0-9]{64})\\b", error) != 0)
        return -1;
    *out = &kickbox_detector;
    return 0;
}
