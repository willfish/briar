/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/humanity/humanity.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { HUMANITY_ABORT = -1, HUMANITY_KEEP = 0, HUMANITY_DROP = 1 } humanity_outcome;

static int humanity_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static humanity_outcome humanity_verify(const br_scan_ctx *ctx, br_slice key,
                                         br_result *result, char **error)
{
    static const char prefix[] = "https://www.humanity.com/api/v2/me?access_token=";
    if (key.len > SIZE_MAX - sizeof(prefix)) {
        humanity_fail(error, "Humanity URL too large");
        return HUMANITY_ABORT;
    }
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) {
        humanity_fail(error, "cannot construct Humanity URL");
        return HUMANITY_ABORT;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* The full literal query is assembled before NewRequestWithContext can
     * reject a nil context and drop the already-constructed finding. */
    if (!ctx) {
        free(url);
        return HUMANITY_DROP;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    humanity_outcome outcome = HUMANITY_KEEP;
    /* Source suppresses every Do error. Shared ABI1 preparation failures are
     * in that same mixed domain; neither classify them nor invoke a setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error) outcome = HUMANITY_DROP;
        else result->verified = br_slice_find(response.body,
            (br_slice){(const unsigned char *)"name", 4}, 0) != SIZE_MAX;
    }
    /* ReadAll precedes the marker check at every status. Original URL/captures
     * survive this one release per attempt, including failed shared setup.
     * Synthesized headers/UA end at send return. Do not reproduce source's
     * scan-deferred closes or response leaks on Do errors. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return outcome;
}

static int humanity_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return humanity_fail(error, "invalid or uninitialized Humanity scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        humanity_outcome outcome = HUMANITY_KEEP;
        /* TrimSpace cannot change this ASCII capture. Keep original ordered
         * occurrences and duplicates without hex, entropy or key validation. */
        if (key.len != 40) {
            humanity_fail(&owned_error, "invalid Humanity capture");
            outcome = HUMANITY_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            humanity_fail(&owned_error, "cannot create Humanity result");
            outcome = HUMANITY_ABORT;
        } else if (verify) {
            outcome = humanity_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == HUMANITY_KEEP && br_results_push(out, &result) != 0) {
            humanity_fail(&owned_error, "cannot append Humanity result");
            outcome = HUMANITY_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HUMANITY_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const humanity_keywords[] = {"humanity"};
static br_detector humanity_detector = {
    .type = 508, .version = 0, .name = "Humanity", .custom_name = "",
    .description = "Humanity is a workforce management platform. Humanity API keys can be used to access and manage workforce data and operations.",
    .keywords = humanity_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = humanity_scan,
};

int br_humanity_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return humanity_fail(error, "invalid Humanity detector output");
    *out = NULL;
    if (br_key_pattern_init(&humanity_detector, "\\b([0-9a-z]{40})\\b", error) != 0)
        return -1;
    *out = &humanity_detector;
    return 0;
}
