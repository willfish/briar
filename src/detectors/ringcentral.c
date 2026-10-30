/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ringcentral/ringcentral.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

enum { RING_KEEP = 0, RING_DROP = 1, RING_FATAL = -1 };

static int ring_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return RING_FATAL;
}

/* Go 1.26.7 url.Parse splits the first '#' before C0/DEL checks. Query '%' is
 * not a constructor error. A fragment '%' in this grammar is always '%com…'. */
static int ring_url_ok(const unsigned char *url, size_t len, char **error)
{
    const unsigned char *hash = memchr(url, '#', len);
    size_t before = hash ? (size_t)(hash - url) : len;
    for (size_t i = 0; i < before; ++i)
        if (url[i] < 0x20 || url[i] == 0x7f) return RING_DROP;
    if (!hash) return RING_KEEP;
    size_t frag = len - (size_t)(hash + 1 - url);
    if (memchr(hash + 1, '\0', frag))
        return ring_fail(error, "unsupported: RingCentral embedded NUL in URL fragment");
    if (memchr(hash + 1, '%', frag)) return RING_DROP;
    return RING_KEEP;
}

static int ring_verify(const br_scan_ctx *ctx, br_slice key, br_slice uri, br_result *result,
                       char **error)
{
    static const char prefix[] =
        "https://platform.devtest.ringcentral.com/restapi/oauth/authorize?response_type=code&redirect_uri=";
    static const char middle[] = "&client_id=";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(middle) - 1;
    if (key.len > SIZE_MAX - fixed || uri.len > SIZE_MAX - fixed - key.len)
        return ring_fail(error, "RingCentral URL size overflow");
    size_t size = fixed + uri.len + key.len;
    char *url = malloc(size + 1);
    if (!url) return ring_fail(error, "cannot allocate RingCentral URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, uri.data, uri.len);
    memcpy(url + sizeof(prefix) - 1 + uri.len, middle, sizeof(middle) - 1);
    memcpy(url + fixed + uri.len, key.data, key.len);
    url[size] = '\0';
    int outcome = ring_url_ok((const unsigned char *)url, size, error);
    /* Complete URL exists before the known nil-context constructor skip. */
    if (outcome == RING_KEEP && !ctx) outcome = RING_DROP;
    if (outcome == RING_KEEP) {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) == 0)
            result->verified = response.status >= 200 && response.status < 300;
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(url);
    return outcome;
}

static int ring_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !out || (!input.data && input.len))
        return ring_fail(error, "invalid or uninitialized RingCentral scan");
    size_t original_len = out->len;
    br_captures keys = {0}, uris = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &uris, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t u = 0; rc == 0 && u < uris.len; ++u) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            int outcome = RING_KEEP;
            /* TrimSpace is a no-op. URI is not stored. Duplicates remain. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                outcome = ring_fail(&owned_error, "cannot create RingCentral result");
            else if (verify)
                outcome = ring_verify(ctx, key, br_captures_at(&uris, u), &result, &owned_error);
            if (outcome == RING_FATAL) rc = -1;
            if (outcome == RING_DROP) {
                br_result_clear(&result);
                continue;
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = ring_fail(&owned_error, "cannot append RingCentral result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&uris);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ring_keywords[] = {"ringcentral"};
static const char *const ring_prefix[] = {"ringcentral"};
static br_regex *ring_patterns[2];
static br_detector ring_detector = {
    .type = 422, .version = 0, .name = "RingCentral", .custom_name = "",
    .description = "RingCentral is a cloud-based communication system that offers messaging, video conferencing, and phone services. RingCentral API keys can be used to access and manage these services.",
    .keywords = ring_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = ring_scan,
};

int br_ringcentral_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ring_fail(error, "invalid RingCentral detector output");
    *out = NULL;
    if (!ring_patterns[0] &&
        br_regex_compile_prefixed(ring_prefix, 1, "\\b([0-9A-Za-z_-]{22})\\b",
                                  &ring_patterns[0], error) != 0)
        return -1;
    /* The dot after www is any non-LF byte, matching the unescaped Go pattern. */
    if (!ring_patterns[1] &&
        br_regex_compile_prefixed(ring_prefix, 1, "\\b(https://www.[0-9A-Za-z_-]{1,}.com)\\b",
                                  &ring_patterns[1], error) != 0)
        return -1;
    ring_detector.state = ring_patterns;
    *out = &ring_detector;
    return 0;
}
