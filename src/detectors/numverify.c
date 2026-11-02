/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/numverify/numverify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { NUM_ABORT = -1, NUM_KEEP = 0, NUM_DROP = 1 } num_outcome;
typedef struct {
    br_http_response response;
    char *url;
} num_held;
typedef struct {
    num_held *items;
    size_t len, cap;
} num_pending;

static const char num_prefix[] = "https://apilayer.net/api/validate?access_key=";
static const char num_suffix[] = "&number=14158586273";
static const char num_country[] = "country_code";
static const char num_restricted[] =
    "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";

static int num_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void num_drain(const br_scan_ctx *ctx, num_pending *pending)
{
    while (pending->len) {
        num_held *item = &pending->items[--pending->len];
        br_http_release(ctx, &item->response);
        free(item->url);
    }
    free(pending->items);
    *pending = (num_pending){0};
}

static int num_hold(num_pending *pending, const br_http_response *response, char *url, char **error)
{
    if (pending->len == pending->cap) {
        if (pending->cap > SIZE_MAX / sizeof(*pending->items) / 2)
            return num_fail(error, "cannot retain Numverify response");
        size_t cap = pending->cap ? pending->cap * 2 : 2;
        num_held *items = realloc(pending->items, cap * sizeof(*items));
        if (!items) return num_fail(error, "cannot retain Numverify response");
        pending->items = items;
        pending->cap = cap;
    }
    pending->items[pending->len++] = (num_held){*response, url};
    return 0;
}

static bool num_needle(br_slice body)
{
    const br_slice country = {(const unsigned char *)num_country, sizeof(num_country) - 1};
    const br_slice restricted = {(const unsigned char *)num_restricted, sizeof(num_restricted) - 1};
    return br_slice_find(body, country, 0) != SIZE_MAX || br_slice_find(body, restricted, 0) != SIZE_MAX;
}

static num_outcome num_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              num_pending *pending, char **error)
{
    const size_t fixed = sizeof(num_prefix) + sizeof(num_suffix) - 1;
    if (key.len > SIZE_MAX - fixed) {
        num_fail(error, "Numverify URL too large");
        return NUM_ABORT;
    }
    char *url = malloc(fixed + key.len);
    if (!url) {
        num_fail(error, "cannot allocate Numverify URL");
        return NUM_ABORT;
    }
    /* Complete literal URL before NewRequestWithContext. No escaping. */
    size_t at = sizeof(num_prefix) - 1;
    memcpy(url, num_prefix, at);
    memcpy(url + at, key.data, key.len);
    at += key.len;
    memcpy(url + at, num_suffix, sizeof(num_suffix));
    /* A nil context drops after the URL exists. A zeroed context is not nil. */
    if (!ctx) {
        free(url);
        return NUM_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* A failed Do or preparation releases immediately. Do not retain the
     * synthesized User-Agent array, and do not rebuild the URL after send. */
    if (sent != 0) {
        br_http_release(ctx, &response);
        free(url);
        return NUM_KEEP;
    }
    /* A read error wins before either needle, including a partial body.
     * Only a completed 2xx body can verify, and either needle is enough. */
    if (!response.body_error && response.status >= 200 && response.status < 300)
        result->verified = num_needle(response.body);
    if (num_hold(pending, &response, url, error) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return NUM_ABORT;
    }
    return NUM_KEEP;
}

static int num_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return num_fail(error, "invalid or uninitialized Numverify scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    num_pending pending = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        num_outcome outcome = NUM_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = num_fail(&owned_error, "cannot create Numverify result");
        else if (verify)
            outcome = num_verify(ctx, key, &result, &pending, &owned_error);
        if (rc == 0 && outcome == NUM_ABORT) rc = -1;
        if (rc == 0 && outcome == NUM_KEEP && br_results_push(out, &result) != 0)
            rc = num_fail(&owned_error, "cannot append Numverify result");
        br_result_clear(&result);
    }
    /* Scanner-return LIFO, after publication and on a later fatal path.
     * Each original URL stays alive through its own release. */
    num_drain(ctx, &pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const num_keywords[] = {"numverify"};
static br_detector num_detector = {
    .type = 439, .version = 0, .name = "Numverify", .custom_name = "",
    .description = "Numverify is a service used to validate phone numbers and gather information about them. Numverify API keys can be used to access this service and validate phone numbers.",
    .keywords = num_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = num_scan,
};

int br_numverify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return num_fail(error, "invalid Numverify detector output");
    *out = NULL;
    if (br_key_pattern_init(&num_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &num_detector;
    return 0;
}
