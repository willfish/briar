/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/juro/juro.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { JURO_ABORT = -1, JURO_KEEP = 0, JURO_DROP = 1 } juro_outcome;

static int juro_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static juro_outcome juro_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* NewRequestWithContext fails before Header.Add. A nil context drops
     * this occurrence and is not a send. This fixed URL cannot fail to parse. */
    if (!ctx) return JURO_DROP;
    /* Header.Add canonicalizes x-api-key to X-Api-Key before Do. Briar does not. */
    const br_header headers[] = {{"X-Api-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.juro.com/v3/templates",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Do and shared preparation failures stay unverified. Source never reads
     * the body, so a read error cannot change status or publication. No setter.
     * The canonical header and key stay alive through this one release. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return JURO_KEEP;
}

static int juro_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return juro_fail(error, "invalid or uninitialized Juro scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        juro_outcome outcome = JURO_KEEP;
        /* TrimSpace cannot change this class. Keep ordered duplicates.
         * Do not use br_scan_key: a constructor drop must not be published. */
        if (key.len != 40) {
            juro_fail(&owned_error, "invalid Juro capture");
            outcome = JURO_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            juro_fail(&owned_error, "cannot create Juro result");
            outcome = JURO_ABORT;
        } else if (verify) {
            outcome = juro_verify(ctx, key, &result);
        }
        if (outcome == JURO_KEEP && br_results_push(out, &result) != 0) {
            juro_fail(&owned_error, "cannot append Juro result");
            outcome = JURO_ABORT;
        }
        br_result_clear(&result);
        if (outcome == JURO_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const juro_keywords[] = {"juro"};
static br_detector juro_detector = {
    .type = 295, .version = 0, .name = "Juro", .custom_name = "",
    .description = "Juro is a contract automation platform. Juro API keys can be used to access and manage contract templates and other resources in Juro.",
    .keywords = juro_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = juro_scan,
};

int br_juro_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return juro_fail(error, "invalid Juro detector output");
    *out = NULL;
    if (br_key_pattern_init(&juro_detector, "\\b([a-zA-Z0-9]{40})\\b", error) != 0)
        return -1;
    *out = &juro_detector;
    return 0;
}
