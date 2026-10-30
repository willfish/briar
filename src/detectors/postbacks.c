/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/postbacks/postbacks.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

/* Raw-string body, including the literal backslash-quote sequences. */
static const char postbacks_body[] =
    "{\"url\": \"https://foo.com/bar\",\"send_at\": 1579049877,"
    "\"body_string\": \"{ \\\"email_id\\\":\\\"123456789\\\" }\"}";
static const char postbacks_url[] = "https://api.postbacks.io/v1/requestPostback";

static int postbacks_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool postbacks_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    _Static_assert(sizeof(postbacks_body) - 1 == 100, "Postbacks body is the 100-byte source literal");
    /* Body and URL are complete before the nil-context drop. Timeout is the
     * source's per-verify assignment on the shared Sane client, not its 5s default. */
    if (!ctx) return false;
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Postbacks-Authorization", key},
    };
    const br_http_request request = {
        .method = "POST", .url = postbacks_url, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)postbacks_body, sizeof(postbacks_body) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int postbacks_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return postbacks_fail(error, "invalid or uninitialized Postbacks scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 36)
            rc = postbacks_fail(&owned_error, "invalid Postbacks capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = postbacks_fail(&owned_error, "cannot create Postbacks result");
        else if (verify)
            keep = postbacks_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = postbacks_fail(&owned_error, "cannot append Postbacks result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const postbacks_keywords[] = {"postbacks"};
static br_detector postbacks_detector = {
    .type = 822, .version = 0, .name = "Postbacks", .custom_name = "",
    .description = "Postbacks are used to send data to a specified URL based on certain events or triggers. Postback URLs are often used in affiliate marketing, ad tracking, and analytics.",
    .keywords = postbacks_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = postbacks_scan,
};

int br_postbacks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return postbacks_fail(error, "invalid Postbacks detector output");
    *out = NULL;
    if (br_key_pattern_init(&postbacks_detector,
                            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                            error) != 0)
        return -1;
    *out = &postbacks_detector;
    return 0;
}
