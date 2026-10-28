/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/frameio/frameio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int frameio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void frameio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Reached only AFTER constructor handling. Content-Type precedes the
     * complete bounded Bearer value, just as in the source. Exact 70-byte
     * capture means 77 auth bytes plus NUL, without heap/formatter/cap seams. */
    br_header headers[2];
    headers[0] = (br_header){"Content-Type", "application/json"};
    char authorization[78];
    _Static_assert(7 + 70 + 1 == sizeof(authorization), "FrameIO Bearer: 77 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.frame.io/v2/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* WHOLE mixed shared setup/allocation/Do domain suppresses to false KEPT,
     * never a setter, diagnostic classifier, success break or guard bypass. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack auth survives synchronous send AND release. All body/read
     * errors ignored. Source scan-defers Close-only; eager owned release/Reader,
     * native/private-client/error-chain/regexp and global engine/output parity
     * remain partial. Native HTTP guards are unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int frameio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return frameio_fail(error, "invalid or uninitialized FrameIO scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* Original occurrences/duplicates; TrimSpace is a no-op. Owned finding
         * failure precedes the known nil-context constructor SKIP. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = frameio_fail(&owned_error, "cannot create FrameIO finding");
        else if (!verify || ctx) {
            if (verify) frameio_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0) rc = frameio_fail(&owned_error, "cannot append FrameIO finding");
        } /* Constructor continue: no invented false finding/append for nil context. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const frameio_keywords[] = {"fio-u-"};
static br_detector frameio_detector = {
    .type = 199, .version = 0, .name = "FrameIO", .custom_name = "",
    .description = "Frame.io is a video review and collaboration platform. Frame.io API keys can be used to access and manage video projects and assets.",
    .keywords = frameio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = frameio_scan,
};

int br_frameio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return frameio_fail(error, "invalid FrameIO detector output");
    *out = NULL;
    if (!frameio_detector.state) {
        br_regex *regex = NULL;
        /* DIRECT case-sensitive source pattern, not a provider/keyword prefix,
         * JWT parser or full-token-alphabet delimiter. Keep fixed-width word
         * boundaries even when final payload bytes are non-word hyphens. */
        if (br_regex_compile("\\b(fio-u-[0-9a-zA-Z_-]{64})\\b", &regex, error) != 0) return -1;
        frameio_detector.state = regex;
    }
    *out = &frameio_detector;
    return 0;
}
