/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hellosign/hellosign.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { HELLOSIGN_ABORT = -1, HELLOSIGN_KEEP = 0, HELLOSIGN_SKIP = 1 } hellosign_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static hellosign_outcome verify_hellosign(const br_scan_ctx *ctx, br_slice key,
                                         br_result *result, char **error)
{
    /* NewRequestWithContext precedes SetBasicAuth; nil context skips the
     * finding without reaching the encoder, unlike Chartmogul. */
    if (!ctx) return HELLOSIGN_SKIP;
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return HELLOSIGN_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.hellosign.com/v3/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses every Do error and never reads the body. Shared ABI1
     * setup errors inhabit that same domain, without diagnostic classifiers. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original auth/captures survive release; synthesized ABI1 headers/UA
     * survive send only. Per-attempt release replaces source's deferred Close. */
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return HELLOSIGN_KEEP;
}

static int scan_hellosign(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized HelloSign scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        hellosign_outcome outcome = HELLOSIGN_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op on this alphabet. Preserve occurrences, including
         * duplicates and nonword capture edges admitted by contextual \b. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create HelloSign finding");
            outcome = HELLOSIGN_ABORT;
        } else if (verify) {
            outcome = verify_hellosign(ctx, key, &result, &owned_error);
        }
        if (outcome == HELLOSIGN_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append HelloSign finding");
            outcome = HELLOSIGN_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HELLOSIGN_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"hellosign"};
static br_detector hellosign = {
    .type = 395, .version = 0, .name = "HelloSign", .custom_name = "",
    .description = "HelloSign is an eSignature provider that allows users to sign documents online. HelloSign API keys can be used to interact with the HelloSign API for managing and sending documents.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_hellosign,
};

int br_hellosign_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid HelloSign detector output");
    *out = NULL;
    if (br_key_pattern_init(&hellosign, "\\b([a-zA-Z-0-9/+]{64})\\b", error) != 0) return -1;
    *out = &hellosign;
    return 0;
}
