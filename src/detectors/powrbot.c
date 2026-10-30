/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/powrbot/powrbot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char powrbot_url[] = "https://powrbot.com/api/v1/search/single/?company=Apple";
/* The pinned Sprintf is "secret-key %s". The prefix is 11 bytes, so the value
 * is 51 bytes. A 50-byte count would drop the required space. */
_Static_assert(sizeof(powrbot_url) - 1 == 55, "Powrbot URL is 55 bytes");
_Static_assert(sizeof("secret-key ") - 1 + 40 == 51, "Powrbot authorization is 51 bytes");

static int powrbot_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int powrbot_authorization(br_slice key, char value[52], char **error)
{
    if (!key.data || key.len != 40 || memchr(key.data, 0, key.len))
        return powrbot_fail(error, "invalid Powrbot key capture");
    int n = snprintf(value, 52, "secret-key %.*s", 40, (const char *)key.data);
    /* Every count other than the complete 51-byte value is fatal, including +1. */
    return n == 51 ? 0 : powrbot_fail(error, "cannot format Powrbot authorization");
}

static int powrbot_verify(const br_scan_ctx *ctx, br_slice key, bool *verified, char **error)
{
    /* Nil context was dropped by the caller before this header is built. */
    char authorization[52];
    br_header header = {"Authorization", NULL};
    br_http_request request = {
        .method = "GET", .url = powrbot_url, .headers = &header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 243,
    };
    if (powrbot_authorization(key, authorization, error) != 0) return -1;
    header.value = authorization;
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    bool accepted = sent == 0 && response.status >= 200 && response.status < 300;
    /* Send failure, including a consumed NULL leaf, stays false with no setter
     * and no invented diagnostic. Body bytes and body_error are ignored.
     * Keep the original URL, key and Authorization live through one release. */
    br_http_release(ctx, &response);
    free(send_error);
    *verified = accepted;
    return 0;
}

static int powrbot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return powrbot_fail(error, "invalid or uninitialized Powrbot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Occurrences stay in order, including duplicates. The captured alphabet
     * makes the source TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = powrbot_fail(&owned_error, "cannot create Powrbot finding");
        if (rc == 0 && verify) {
            /* Fixed valid URL: nil context is the constructor's ordinary drop.
             * It happens before Authorization and is not a false-kept finding. */
            if (!ctx) { br_result_clear(&result); continue; }
            rc = powrbot_verify(ctx, key, &result.verified, &owned_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = powrbot_fail(&owned_error, "cannot append Powrbot finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        powrbot_fail(&owned_error, "cannot collect Powrbot tokens");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const powrbot_keywords[] = {"powrbot"};
static br_detector powrbot_detector = {
    .type = 243, .version = 0, .name = "Powrbot", .custom_name = "",
    .description = "Powrbot is a service that provides company information. Powrbot API keys can be used to access and retrieve data from their database.",
    .keywords = powrbot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = powrbot_scan,
};

int br_powrbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return powrbot_fail(error, "invalid Powrbot detector output");
    *out = NULL;
    if (!powrbot_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(powrbot_keywords, 1, "\\b([a-z0-9A-Z]{40})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        powrbot_detector.state = pattern;
    }
    *out = &powrbot_detector;
    return 0;
}
