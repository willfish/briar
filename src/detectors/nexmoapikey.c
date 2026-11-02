/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nexmoapikey/nexmoapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } nexmo_patterns;
typedef struct {
    br_http_response response;
    char *url;
} nexmo_held;
typedef struct {
    nexmo_held *items;
    size_t len, cap;
} nexmo_pending;

static const char nexmo_prefix[] = "https://rest.nexmo.com/account/get-balance?api_key=";
static const char nexmo_secret_query[] = "&api_secret=";

static int nexmo_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void nexmo_drain(const br_scan_ctx *ctx, nexmo_pending *pending)
{
    while (pending->len) {
        nexmo_held *item = &pending->items[--pending->len];
        br_http_release(ctx, &item->response);
        free(item->url);
    }
    free(pending->items);
    *pending = (nexmo_pending){0};
}

static int nexmo_hold(nexmo_pending *pending, const br_http_response *response, char *url, char **error)
{
    if (pending->len == pending->cap) {
        if (pending->cap > SIZE_MAX / sizeof(*pending->items) / 2)
            return nexmo_fail(error, "cannot retain NexmoApiKey response");
        size_t cap = pending->cap ? pending->cap * 2 : 2;
        nexmo_held *items = realloc(pending->items, cap * sizeof(*items));
        if (!items) return nexmo_fail(error, "cannot retain NexmoApiKey response");
        pending->items = items;
        pending->cap = cap;
    }
    pending->items[pending->len++] = (nexmo_held){*response, url};
    return 0;
}

static int nexmo_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret,
                        br_result *result, nexmo_pending *pending, bool *keep, char **error)
{
    const size_t fixed = sizeof(nexmo_prefix) + sizeof(nexmo_secret_query) - 1;
    if (key.len > SIZE_MAX - fixed || secret.len > SIZE_MAX - fixed - key.len)
        return nexmo_fail(error, "NexmoApiKey URL too large");
    char *url = malloc(fixed + key.len + secret.len);
    if (!url) return nexmo_fail(error, "cannot allocate NexmoApiKey URL");
    /* Complete literal URL before NewRequestWithContext. No escaping. */
    size_t at = sizeof(nexmo_prefix) - 1;
    memcpy(url, nexmo_prefix, at);
    memcpy(url + at, key.data, key.len); at += key.len;
    memcpy(url + at, nexmo_secret_query, sizeof(nexmo_secret_query) - 1);
    at += sizeof(nexmo_secret_query) - 1;
    memcpy(url + at, secret.data, secret.len); at += secret.len;
    url[at] = '\0';
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* A failed Do or preparation releases immediately. The synthesized
     * User-Agent array dies when send returns; do not retain or rebuild it. */
    if (sent != 0) {
        br_http_release(ctx, &response);
        free(url);
        return 0;
    }
    /* Successful Close waits until this scan returns. The original URL stays
     * the allocation above; do not rebuild it after send. */
    result->verified = response.status >= 200 && response.status < 300;
    if (nexmo_hold(pending, &response, url, error) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return -1;
    }
    return 0;
}

static int nexmo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nexmo_fail(error, "invalid or uninitialized NexmoApiKey scan");
    const nexmo_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->secret)
        return nexmo_fail(error, "invalid or uninitialized NexmoApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    nexmo_pending pending = {0};
    char *owned_error = NULL;
    /* Independent sets. Hyphen is not a word character, so ASCII \b stays.
     * Duplicates remain. Span 1024 is an engine hint, not a scan cap. */
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            br_result result = {0};
            bool keep = true;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret",
                                      (br_slice){0}) != 0)
                rc = nexmo_fail(&owned_error, "cannot create NexmoApiKey result");
            else if (verify)
                rc = nexmo_verify(ctx, key, secret, &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = nexmo_fail(&owned_error, "cannot append NexmoApiKey result");
            br_result_clear(&result);
        }
    }
    /* Scanner-return LIFO, after publication and on a later fatal path.
     * Each original URL stays alive through its own release. */
    nexmo_drain(ctx, &pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static nexmo_patterns nexmo_compiled;
static const char *const nexmo_keywords[] = {"nexmo"};
static const br_detector nexmo_detector = {
    .type = 121, .version = 0, .name = "NexmoApiKey", .custom_name = "",
    .description = "Nexmo provides APIs for SMS, voice, phone verifications, and more. Nexmo API keys can be used to access and manage these services.",
    .keywords = nexmo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &nexmo_compiled, .scan = nexmo_scan,
};

int br_nexmoapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nexmo_fail(error, "invalid NexmoApiKey detector output");
    *out = NULL;
    if (!nexmo_compiled.key && br_regex_compile_prefixed(nexmo_keywords, 1,
            "\\b([A-Za-z0-9_-]{8})\\b", &nexmo_compiled.key, error) != 0) return -1;
    if (!nexmo_compiled.secret && br_regex_compile_prefixed(nexmo_keywords, 1,
            "\\b([A-Za-z0-9_-]{16})\\b", &nexmo_compiled.secret, error) != 0) return -1;
    *out = &nexmo_detector;
    return 0;
}
