/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/parseur/parseur.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum { PARSEUR_ABORT = -1, PARSEUR_KEEP = 0 } parseur_outcome;

static int parseur_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static parseur_outcome parseur_verify(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    /* Token header is not built when NewRequestWithContext fails. The fixed
     * URL cannot fail to parse, so nil context is the reachable constructor
     * error. Setter still runs and the finding is published. */
    const char *cause = NULL;
    char authorization[6 + 40 + 1];
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        memcpy(authorization, "Token ", 6);
        memcpy(authorization + 6, key.data, key.len);
        authorization[6 + key.len] = '\0';
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.parseur.com/",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        /* Every 2xx verifies. Other statuses, including 401, are unverified
         * with a nil error. Body and read errors are ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status >= 200 && response.status < 300)
            result->verified = true;
    }
    br_slice secret = {key.data, key.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc != 0) {
        parseur_fail(error, "cannot set Parseur verification error");
        return PARSEUR_ABORT;
    }
    return PARSEUR_KEEP;
}

static int parseur_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return parseur_fail(error, "invalid or uninitialized Parseur scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Prefix is parseur[^il], not the keyword. Ordered duplicates stay.
     * TrimSpace cannot change this hex class. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        parseur_outcome outcome = PARSEUR_KEEP;
        if (key.len != 40) {
            parseur_fail(&owned_error, "invalid Parseur capture");
            outcome = PARSEUR_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            parseur_fail(&owned_error, "cannot create Parseur result");
            outcome = PARSEUR_ABORT;
        } else if (verify) {
            outcome = parseur_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == PARSEUR_KEEP && br_results_push(out, &result) != 0) {
            parseur_fail(&owned_error, "cannot append Parseur result");
            outcome = PARSEUR_ABORT;
        }
        br_result_clear(&result);
        if (outcome == PARSEUR_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const parseur_keywords[] = {"parseur"};
static br_detector parseur_detector = {
    .type = 837, .version = 0, .name = "Parseur", .custom_name = "",
    .description = "Parseur is a document parsing software used to extract data from emails and other documents. Parseur API keys can be used to access and manage this data.",
    .keywords = parseur_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = parseur_scan,
};

int br_parseur_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return parseur_fail(error, "invalid Parseur detector output");
    *out = NULL;
    if (!parseur_detector.state) {
        const char *const prefix[] = {"parseur[^il]"};
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(prefix, 1, "\\b([a-f0-9]{40})\\b", &pattern, error) != 0)
            return -1;
        parseur_detector.state = pattern;
    }
    *out = &parseur_detector;
    return 0;
}
