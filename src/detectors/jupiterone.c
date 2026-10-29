/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/jupiterone/jupiterone.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Raw source payload, including tabs and escaped quotes. Not compact JSON. */
static const char jupiterone_query[] = "{\n\t\t\t\t\"query\": \"query J1QL($query: String! = \\\"find jupiterone_account\\\", $variables: JSON, $cursor: String, $scopeFilters: [JSON!], $flags: QueryV1Flags) { queryV1(query: $query, variables: $variables, cursor: $cursor, scopeFilters: $scopeFilters, flags: $flags) { type data cursor }}\"\n\t\t\t  }";
_Static_assert(sizeof(jupiterone_query) - 1 == 293, "JupiterOne query body");

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Nil context is a constructor failure and is not a send. Every attempted
 * send has one cleanup path: setter decision, then release, then free.
 * Fatal is before publication, not a skipped release. A NULL Do cause stays
 * NULL. Body is not a verification input. */
static int verify_jupiterone(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, char **error)
{
    if (!ctx) {
        *keep = false;
        return 0;
    }
    if (key.len != 76 || !key.data) return fail(error, "invalid JupiterOne key");
    char authorization[84];
    _Static_assert(sizeof(authorization) == 84, "Bearer value is 83 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 76);
    authorization[83] = '\0';
    const br_header headers[] = {
        {"Authorization", authorization},
        /* Header.Add canonicalizes JupiterOne-Account before Do. Briar keeps the supplied name. */
        {"Jupiterone-Account", "12345678-1234-1234-1234-123412341234"},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://graphql.us.jupiterone.io/",
        .headers = headers, .nheaders = 3,
        .body = {(const unsigned char *)jupiterone_query, sizeof(jupiterone_query) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 982,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool reached_setter = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* Pinned Do(err) always calls SetVerificationError, even when err is nil. */
        cause = transport_error;
        reached_setter = true;
    } else if (response.status == 200) {
        result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format JupiterOne verification status");
        else {
            cause = status_error;
            reached_setter = true;
        }
    }
    if (reached_setter &&
        br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = fail(error, "cannot set JupiterOne verification error");
    /* Request, headers, body, and key remain alive through this release. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_jupiterone(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized JupiterOne scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        /* Finding resources precede the constructor skip. TrimSpace is a no-op.
         * Keep source order, including duplicates from a later keyword. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create JupiterOne finding");
        if (!rc && verify) rc = verify_jupiterone(ctx, key, &result, &keep, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append JupiterOne finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"jupiterone"};
static br_detector jupiterone = {
    .type = 982, .version = 0, .name = "JupiterOne", .custom_name = "",
    .description = "JupiterOne is a cloud security management platform. "
                   "JupiterOne API keys can be used to access and manage security data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_jupiterone,
};

int br_jupiterone_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid JupiterOne detector output");
    *out = NULL;
    if (br_key_pattern_init(&jupiterone, "\\b([0-9a-zA-Z]{76})\\b", error) != 0) return -1;
    *out = &jupiterone;
    return 0;
}
