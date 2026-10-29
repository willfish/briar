/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hunter/hunter.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { HUNTER_ABORT = -1, HUNTER_KEEP = 0, HUNTER_DROP = 1 } hunter_outcome;

static int hunter_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static hunter_outcome hunter_verify(const br_scan_ctx *ctx, br_slice key,
                                     br_result *result, char **error)
{
    static const char prefix[] = "https://api.hunter.io/v2/leads_lists?api_key=";
    if (key.len > SIZE_MAX - sizeof(prefix)) {
        hunter_fail(error, "Hunter URL too large");
        return HUNTER_ABORT;
    }
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) {
        hunter_fail(error, "cannot construct Hunter URL");
        return HUNTER_ABORT;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* Assemble the full literal query before NewRequestWithContext's nil
     * context error drops the already-constructed finding. */
    if (!ctx) {
        free(url);
        return HUNTER_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source ignores the whole Do error domain. ABI1 shared setup errors are
     * mixed into it; do not classify diagnostics or call an error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors are ignored at every status. Original URL/captures
     * survive this one release per attempt, including failed preparation;
     * synthesized request/header-array/UA storage ends at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return HUNTER_KEEP;
}

static int hunter_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hunter_fail(error, "invalid or uninitialized Hunter scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        hunter_outcome outcome = HUNTER_KEEP;
        /* TrimSpace is a no-op for this alphabet. Preserve occurrences,
         * duplicates and contextual hyphen boundaries without token checks. */
        if (key.len != 40) {
            hunter_fail(&owned_error, "invalid Hunter capture");
            outcome = HUNTER_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            hunter_fail(&owned_error, "cannot create Hunter result");
            outcome = HUNTER_ABORT;
        } else if (verify) {
            outcome = hunter_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == HUNTER_KEEP && br_results_push(out, &result) != 0) {
            hunter_fail(&owned_error, "cannot append Hunter result");
            outcome = HUNTER_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HUNTER_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const hunter_keywords[] = {"hunter"};
static br_detector hunter_detector = {
    .type = 72, .version = 0, .name = "Hunter", .custom_name = "",
    .description = "Hunter is a service that helps find and verify professional email addresses. Hunter API keys can be used to access and retrieve data from the Hunter service.",
    .keywords = hunter_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hunter_scan,
};

int br_hunter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hunter_fail(error, "invalid Hunter detector output");
    *out = NULL;
    if (br_key_pattern_init(&hunter_detector, "\\b([a-z0-9_-]{40})\\b", error) != 0)
        return -1;
    *out = &hunter_detector;
    return 0;
}
