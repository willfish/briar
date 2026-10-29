/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/insightly/insightly.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { INSIGHTLY_ABORT = -1, INSIGHTLY_KEEP = 0, INSIGHTLY_DROP = 1 } insightly_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static insightly_outcome verify_insightly(const br_scan_ctx *ctx, br_slice key,
                                          br_result *result, char **error)
{
    br_http_request request = {
        .method = "GET", .url = "https://api.na1.insightly.com/v3.1/Contacts?top=2",
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    /* The fixed constructor rejects nil context before SetBasicAuth. Every
     * nonzero owned encoder result, including +1, is fatal after that point. */
    if (!ctx) return INSIGHTLY_DROP;
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return INSIGHTLY_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    request.headers = headers;
    request.nheaders = 1;
    br_http_response response = {0};
    char *send_error = NULL;
    /* The source suppresses the whole mixed shared setup/Do error domain,
     * never sets a verification error and ignores every body/read failure. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* Provider auth/captures survive ordinary release. Synthesized ABI1
     * headers/UA survive send return only; do not retain prepared requests. */
    free(send_error);
    free(authorization);
    return INSIGHTLY_KEEP;
}

static int scan_insightly(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Insightly scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        insightly_outcome outcome = INSIGHTLY_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op on this alphabet. Keep occurrences, duplicates
         * and contextual hyphen edges; this is not UUID/whole-token validation. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create Insightly finding");
            outcome = INSIGHTLY_ABORT;
        } else if (verify) {
            outcome = verify_insightly(ctx, key, &result, &owned_error);
        }
        if (outcome == INSIGHTLY_KEEP && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Insightly finding");
            outcome = INSIGHTLY_ABORT;
        }
        br_result_clear(&result);
        if (outcome == INSIGHTLY_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"insightly"};
static br_detector insightly = {
    .type = 271, .version = 0, .name = "Insightly", .custom_name = "",
    .description = "Insightly is a customer relationship management (CRM) platform. Insightly API keys can be used to access and manage CRM data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_insightly,
};

int br_insightly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Insightly detector output");
    *out = NULL;
    if (br_key_pattern_init(&insightly, "\\b([a-z0-9-]{36})\\b", error) != 0) return -1;
    *out = &insightly;
    return 0;
}
