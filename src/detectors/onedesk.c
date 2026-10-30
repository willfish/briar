/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/onedesk/onedesk.go. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *email, *password; } onedesk_state;
typedef struct { bool verified, drop; } onedesk_verdict;

static int onedesk_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int onedesk_payload(br_slice email, br_slice password, br_bytes *body, char **error)
{
    /* Literal fmt.Sprintf, NOT JSON encoding: keep internal quotes, escapes,
     * controls, case and bytes even when the resulting JSON is invalid. */
    if ((!email.data && email.len) || (!password.data && password.len) ||
        email.len > SIZE_MAX - 29 || password.len > SIZE_MAX - 29 - email.len)
        return onedesk_fail(error, "invalid or oversized Onedesk payload");
    size_t len = 29 + email.len + password.len;
    if (len > INT_MAX) return onedesk_fail(error, "Onedesk payload exceeds formatter capacity");
    body->data = malloc(len + 1);
    if (!body->data) return onedesk_fail(error, "cannot allocate Onedesk payload");
    body->len = len;
    int n = snprintf((char *)body->data, len + 1, "{\"email\": \"%.*s\", \"password\": \"%.*s\"}",
                     (int)email.len, (const char *)email.data,
                     (int)password.len, (const char *)password.data);
    /* snprintf has an ordinary byte-count domain; only the complete count is
     * success. Caller frees the owned buffer on EVERY return, including +1. */
    return n >= 0 && (size_t)n == len ? 0 : onedesk_fail(error, "cannot format Onedesk payload");
}

static int onedesk_verify(const br_scan_ctx *ctx, br_slice payload,
                           onedesk_verdict *verdict, char **error)
{
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://app.onedesk.com/rest/2.0/login/loginUser",
        .headers = headers, .nheaders = 1, .body = payload,
        .profile = BR_HTTP_SANE, .detector_type = 601,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        /* ReadAll precedes EVERY status decision. A non-NULL read error, EVEN
         * empty text/complete marker bytes, drops without inspecting the slice. */
        if (response.body_error) verdict->drop = true;
        else if ((!response.body.data && response.body.len) || response.body.len > (size_t)PTRDIFF_MAX)
            rc = onedesk_fail(error, "invalid Onedesk response body");
        else if (response.status >= 200 && response.status < 300) {
            static const unsigned char marker[] = "\"code\":\"SUCCESS\"";
            _Static_assert(sizeof(marker) - 1 == 16, "Onedesk success marker is 16 bytes");
            verdict->verified = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    /* WHOLE mixed preparation/Do nonzero retains false. NO setter on ANY path.
     * Original payload/email/password/header/URL stay live through ONE release;
     * ordinary prepared headers/UA already expired at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int onedesk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return onedesk_fail(error, "invalid or uninitialized Onedesk scan");
    const onedesk_state *state = detector->state;
    size_t original_len = out->len;
    br_captures passwords = {0}, emails = {0};
    char *owned_error = NULL;
    /* Scan order differs from initialization: ALL password occurrences first,
     * then ALL byte-unique emails, EVEN with zero passwords. TrimSpace is a
     * no-op on both grammars' outer bytes, not on their preserved internals. */
    int rc = br_captures_find(state->password, input, &passwords, false, &owned_error);
    if (rc == 0) rc = br_captures_find(state->email, input, &emails, true, &owned_error);
    for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
        br_slice email = br_captures_at(&emails, e);
        for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
            br_slice password = br_captures_at(&passwords, p);
            br_result result = {0};
            onedesk_verdict verdict = {0};
            /* Password is required but hidden in EVERY output field. */
            if (br_finding_key_bytes(&result, detector->type, email, "key") != 0)
                rc = onedesk_fail(&owned_error, "cannot create Onedesk finding");
            if (rc == 0 && verify) {
                br_bytes body = {0};
                rc = onedesk_payload(email, password, &body, &owned_error);
                if (rc == 0) {
                    /* COMPLETE owned raw payload BEFORE nil constructor DROP. */
                    if (!ctx) verdict.drop = true;
                    else rc = onedesk_verify(ctx, (br_slice){body.data, body.len}, &verdict, &owned_error);
                }
                free(body.data); /* After release, or before any send on nil/failure. */
                if (rc == 0) result.verified = verdict.verified;
            }
            if (rc == 0 && !verdict.drop && br_results_push(out, &result) != 0)
                rc = onedesk_fail(&owned_error, "cannot append Onedesk finding");
            br_result_clear(&result);
        }
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        onedesk_fail(&owned_error, "cannot collect Onedesk credentials");
    }
    br_captures_clear(&emails);
    br_captures_clear(&passwords);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const onedesk_keywords[] = {"onedesk"};
static onedesk_state onedesk_patterns;
static br_detector onedesk_detector = {
    .type = 601, .version = 0, .name = "Onedesk", .custom_name = "",
    .description = "Onedesk is a customer service and project management software. Onedesk credentials can be used to access and manage customer service tickets and project tasks.",
    .keywords = onedesk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = onedesk_scan,
};

int br_onedesk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return onedesk_fail(error, "invalid Onedesk detector output");
    *out = NULL;
    if (!onedesk_detector.state) {
        br_regex *email = NULL, *password = NULL;
        /* Source init order: email FIRST, password SECOND; no partial cache. */
        int rc = br_regex_compile(br_email_pattern, &email, error);
        if (rc == 0) rc = br_regex_compile_prefixed(onedesk_keywords, 1,
                           "\\b([a-zA-Z0-9!=@#$%^]{8,64})", &password, error);
        if (rc != 0) { br_regex_free(password); br_regex_free(email); return -1; }
        onedesk_patterns = (onedesk_state){email, password};
        onedesk_detector.state = &onedesk_patterns;
    }
    *out = &onedesk_detector;
    return 0;
}
