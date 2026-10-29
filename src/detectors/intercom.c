/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/intercom/intercom.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

static int intercom_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int intercom_trim(br_slice capture, br_slice *trimmed, char **error)
{
    size_t begin = 0, end = 0;
    for (size_t at = 0; at < capture.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){capture.data + at, capture.len - at}, &rune);
        if (!width) return intercom_fail(error, "cannot decode Intercom capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at + width;
        else if (at == begin) begin += width;
        at += width;
    }
    if (end < begin) end = begin;
    *trimmed = (br_slice){capture.data + begin, end - begin};
    return 0;
}

static int intercom_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, char **error)
{
    /* The fixed NewRequestWithContext fails on nil before adding auth. */
    if (!ctx) { *keep = false; return 0; }
    if (key.len > SIZE_MAX - sizeof("Bearer "))
        return intercom_fail(error, "Intercom authorization too large");
    char *authorization = malloc(sizeof("Bearer ") + key.len);
    if (!authorization)
        return intercom_fail(error, "cannot allocate Intercom authorization");
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key.data, key.len);
    authorization[sizeof("Bearer ") - 1 + key.len] = '\0';
    const br_header headers[] = {
        {"Authorization", authorization}, {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.intercom.io/contacts?per_page=5",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole mixed shared setup/Do failure domain. Bodies and
     * read failures are ignored; CR/LF in auth still reaches header validation. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* Provider originals survive release, not synthesized ABI1 headers/UA.
     * Ordinary release is eager rather than the source's deferred Close. */
    free(send_error);
    free(authorization);
    return 0;
}

static int intercom_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return intercom_fail(error, "invalid or uninitialized Intercom scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = {0};
        br_bytes decoded = {0};
        br_result result = {0};
        bool keep = true;
        rc = intercom_trim(br_captures_at(&keys, i), &key, &owned_error);
        if (rc == 0) {
            size_t bad_offset;
            int decoded_rc = br_azure_base64_std_decode(key, &decoded, &bad_offset);
            if (decoded_rc == 1) keep = false;
            else if (decoded_rc != 0)
                rc = intercom_fail(&owned_error, "cannot decode Intercom Base64");
            else if (decoded.len < 4 || memcmp(decoded.data, "tok:", 4)) keep = false;
        }
        /* The decoder owns a prefix even on corruption; never accept it then. */
        free(decoded.data);
        if (rc == 0 && keep && br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = intercom_fail(&owned_error, "cannot create Intercom finding");
        if (rc == 0 && keep && verify)
            rc = intercom_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = intercom_fail(&owned_error, "cannot append Intercom finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const intercom_keywords[] = {"intercom"};
static br_detector intercom_detector = {
    .type = 156, .version = 0, .name = "Intercom", .custom_name = "",
    .description = "Intercom is a customer messaging platform that allows businesses to communicate with customers. Intercom tokens can be used to access and manage customer data and communication.",
    .keywords = intercom_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = intercom_scan,
};

int br_intercom_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return intercom_fail(error, "invalid Intercom detector output");
    *out = NULL;
    /* The class union is ALL runes, including CR/LF, NUL and Unicode; only
     * the keyword folds case. No ending boundary or post-trim length check. */
    if (br_key_pattern_init(&intercom_detector, "\\b([a-zA-Z0-9\\W\\S]{59}=)", error) != 0)
        return -1;
    *out = &intercom_detector;
    return 0;
}
