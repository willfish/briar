/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getgist/getgist.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int getgist_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool getgist_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* NewRequestWithContext failure skips this occurrence. */
    /* The fixed URL/method constructor precedes this literal, not Base64, auth. */
    char authorization[7 + 68 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 68);
    authorization[75] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.getgist.com/contacts/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the entire shared setup/Do error domain; body reads are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original auth and capture survive release. Ordinary synthesized headers/UA
     * end at send return. ABI1 releases eagerly, unlike source-deferred close. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int getgist_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getgist_fail(error, "invalid or uninitialized Getgist scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences and duplicates; TrimSpace is a grammar no-op.
     * Finding resources precede constructor skip and shared-send suppression. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 68) rc = getgist_fail(&owned_error, "invalid Getgist capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = getgist_fail(&owned_error, "cannot create Getgist result");
        if (rc == 0 && verify) keep = getgist_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = getgist_fail(&owned_error, "cannot append Getgist result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const getgist_keywords[] = {"getgist"};
static br_detector getgist_detector = {
    .type = 210, .version = 0, .name = "Getgist", .custom_name = "",
    .description = "Getgist is a service used for managing contacts and communications. Getgist API keys can be used to access and manage contact data and communication settings.",
    .keywords = getgist_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = getgist_scan,
};

int br_getgist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getgist_fail(error, "invalid Getgist detector output");
    *out = NULL;
    if (br_key_pattern_init(&getgist_detector, "\\b([a-z0-9A-Z+=]{68})", error) != 0)
        return -1;
    *out = &getgist_detector;
    return 0;
}
