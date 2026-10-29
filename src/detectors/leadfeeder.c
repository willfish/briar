/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/leadfeeder/leadfeeder.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    LEADFEEDER_ABORT = -1,
    LEADFEEDER_KEEP = 0,
    LEADFEEDER_DROP = 1
} leadfeeder_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False publish means the known nil-context constructor failure. Every other
 * mixed setup/Do failure still publishes an unverified finding. */
static leadfeeder_outcome verify_leadfeeder(const br_scan_ctx *ctx, br_slice key,
                                            br_result *result)
{
    /* NewRequestWithContext rejects a nil context before the header exists.
     * Drop that candidate with no send and no release. */
    if (!ctx) return LEADFEEDER_DROP;
    /* Grammar is exactly 43 bytes from [a-zA-Z0-9-]. TrimSpace is a no-op.
     * Keep this provider value alive through send and release. */
    char authorization[56];
    _Static_assert(sizeof(authorization) == 56, "Leadfeeder Token token= value is 55 bytes plus NUL");
    memcpy(authorization, "Token token=", 12);
    memcpy(authorization + 12, key.data, 43);
    authorization[55] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.leadfeeder.com/accounts",
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole mixed setup/Do domain stays unverified. Do not classify its
     * text, set a verification error, or read the body. Status is 2xx only. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return LEADFEEDER_KEEP;
}

static int scan_leadfeeder(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Leadfeeder scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        leadfeeder_outcome outcome = LEADFEEDER_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* Keep every in-range occurrence, including duplicates. Finding
         * failure is fatal before the nil-context drop and before send.
         * br_scan_key cannot express that candidate-only drop. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Leadfeeder finding");
            outcome = LEADFEEDER_ABORT;
        } else if (verify)
            outcome = verify_leadfeeder(ctx, key, &result);
        if (outcome == LEADFEEDER_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Leadfeeder finding");
            outcome = LEADFEEDER_ABORT;
        }
        br_result_clear(&result);
        if (outcome == LEADFEEDER_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"leadfeeder"};
static br_detector leadfeeder = {
    .type = 329,
    .version = 0,
    .name = "Leadfeeder",
    .custom_name = "",
    .description = "Leadfeeder is a tool that shows you the companies visiting your website, how they found you, and what they\xe2\x80\x99re interested in. Leadfeeder API keys can be used to access and manage this data.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_leadfeeder,
};

int br_leadfeeder_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Leadfeeder detector output");
    *out = NULL;
    if (!leadfeeder.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9-]{43})\\b", &regex, error) != 0)
            return -1;
        leadfeeder.state = regex;
    }
    *out = &leadfeeder;
    return 0;
}
