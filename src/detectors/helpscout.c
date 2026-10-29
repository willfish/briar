/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/helpscout/helpscout.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { HELPSCOUT_ABORT = -1, HELPSCOUT_KEEP = 0, HELPSCOUT_SKIP = 1 } helpscout_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static helpscout_outcome verify_helpscout(const br_scan_ctx *ctx, br_slice key,
                                         br_result *result, char **error)
{
    /* NewRequestWithContext precedes SetBasicAuth: a nil context skips this
     * already-constructed finding without reaching the encoder. */
    if (!ctx) return HELPSCOUT_SKIP;
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){(const unsigned char *)"X", 1},
                           &authorization, error) != 0) {
        free(authorization);
        return HELPSCOUT_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://docsapi.helpscout.net/v1/collections",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses all Client.Do errors. ABI1 mixes shared setup failures
     * into that domain too; do not classify diagnostic text or set an error. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore bodies/read errors. Provider-original auth/captures/URL survive
     * release; ordinary ABI1 synthesized headers/UA end at send return. This
     * eager release does not reproduce source's scan-deferred Body.Close. */
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return HELPSCOUT_KEEP;
}

static int scan_helpscout(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Helpscout scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        helpscout_outcome outcome = HELPSCOUT_KEEP;
        /* TrimSpace is a no-op for this lowercase ASCII alphanumeric capture.
         * Preserve source occurrences, including duplicates, without filtering. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Helpscout result");
            outcome = HELPSCOUT_ABORT;
        }
        if (outcome == HELPSCOUT_KEEP && verify)
            outcome = verify_helpscout(ctx, key, &result, &owned_error);
        if (outcome == HELPSCOUT_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Helpscout result");
            outcome = HELPSCOUT_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HELPSCOUT_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"helpscout"};
static br_detector helpscout = {
    .type = 153, .version = 0, .name = "Helpscout", .custom_name = "",
    .description = "Helpscout is a customer service software that provides a help desk for managing customer communications. Helpscout API keys can be used to access and manage customer interactions and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_helpscout,
};

int br_helpscout_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Helpscout detector output");
    *out = NULL;
    if (br_key_pattern_init(&helpscout, "\\b([a-z0-9]{40})\\b", error) != 0) return -1;
    *out = &helpscout;
    return 0;
}
