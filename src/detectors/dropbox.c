/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dropbox/dropbox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../utf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dropbox_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool dropbox_contains(br_slice body, const char *marker)
{
    return br_slice_find(body, (br_slice){(const unsigned char *)marker, strlen(marker)}, 0) != SIZE_MAX;
}

static int dropbox_body_diagnostic(int status, br_slice body, char **owned,
                                    const char **cause, char **error)
{
    /* Only this diagnostic needs text representation. Read errors and ALL
     * binary marker decisions have already won before reaching this guard. */
    if ((body.len && memchr(body.data, 0, body.len)) || !br_utf8_valid(body)) {
        *cause = "unsupported: Dropbox non-UTF-8 or NUL response body diagnostic";
        return 0;
    }
    char prefix[80];
    int n = snprintf(prefix, sizeof(prefix), "unexpected status code: %d, body: ", status);
    if (n < 0 || (size_t)n >= sizeof(prefix))
        return dropbox_fail(error, "cannot format Dropbox body diagnostic");
    if (body.len > SIZE_MAX - (size_t)n - 1)
        return dropbox_fail(error, "Dropbox body diagnostic too large");
    char *text = malloc((size_t)n + body.len + 1);
    if (!text) return dropbox_fail(error, "cannot allocate Dropbox body diagnostic");
    memcpy(text, prefix, (size_t)n);
    if (body.len) memcpy(text + n, body.data, body.len);
    text[(size_t)n + body.len] = '\0';
    *owned = text;
    *cause = text;
    return 0;
}

static int dropbox_verify(const br_scan_ctx *ctx, br_slice token,
                           br_result *result, char **error)
{
    /* Constructor errors retain the candidate, BEFORE Bearer preparation. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return dropbox_fail(error, "cannot set Dropbox verification error");
        return 0;
    }
    static const char bearer[] = "Bearer ";
    if (token.len > SIZE_MAX - sizeof(bearer))
        return dropbox_fail(error, "Dropbox authorization too large");
    /* One complete owned value: tokens are unbounded, not capped by the 4096
     * engine hint. Borrow through synchronous send AND release, with no copy. */
    char *authorization = malloc(sizeof(bearer) + token.len);
    if (!authorization) return dropbox_fail(error, "cannot allocate Dropbox authorization");
    memcpy(authorization, bearer, sizeof(bearer) - 1);
    memcpy(authorization + sizeof(bearer) - 1, token.data, token.len);
    authorization[sizeof(bearer) - 1 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.dropboxapi.com/2/users/get_current_account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *owned_diagnostic = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    /* Retain the WHOLE mixed shared setup/allocation/Do domain as an ordinary
     * leaf cause, without classifying text or supplying redaction secrets. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status == 400 || response.status == 401) {
        /* Source's single-%w read envelope unwraps to this borrowed leaf.
         * A non-NULL empty cause is still a read error; never strip its text. */
        if (response.body_error) cause = response.body_error;
        else if (dropbox_contains(response.body, "missing_scope") ||
                 dropbox_contains(response.body, "does not have the required scope"))
            result->verified = true;
        else if (!dropbox_contains(response.body, "invalid_access_token") &&
                 !dropbox_contains(response.body, "expired_access_token"))
            rc = dropbox_body_diagnostic(response.status, response.body, &owned_diagnostic, &cause, error);
    } else {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = dropbox_fail(error, "cannot format Dropbox status error");
        else cause = status_error;
    }
    /* Copy borrowed body-error causes BEFORE release. NULL is the source's
     * deliberate setter no-op; every nonzero setter result is scan-fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = dropbox_fail(error, "cannot set Dropbox verification error");
    /* Source drains/closes after status/read decisions. ABI1 buffers eagerly
     * and releases now; Reader/drain timing, private-client selection, native
     * POST redirects (still fail-closed), full client/RE2 and global engine/
     * output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(authorization);
    free(transport_error);
    free(owned_diagnostic);
    return rc == 0 ? 0 : -1;
}

static int dropbox_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dropbox_fail(error, "invalid or uninitialized Dropbox scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* Keep full byte-original unique captures, without trimming or local caps.
     * Native first-occurrence order is one choice of upstream's map order. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        /* Finding resources precede construction and every candidate outcome. */
        if (br_finding_key_bytes(&result, detector->type, token, "token") != 0)
            rc = dropbox_fail(&owned_error, "cannot create Dropbox result");
        if (rc == 0 && verify)
            rc = dropbox_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = dropbox_fail(&owned_error, "cannot append Dropbox result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dropbox_keywords[] = {"dropbox", "sl."};
static br_detector dropbox_detector = {
    .type = 18, .version = 0, .name = "Dropbox", .custom_name = "",
    .description = "Dropbox is a file hosting service that offers cloud storage, file synchronization, personal cloud, and client software. Dropbox API keys can be used to access and manage files and folders in a Dropbox account.",
    .keywords = dropbox_keywords, .nkeywords = 2,
    .max_secret_size = 4096, .start_offset = -1, .max_credential_span = -1,
    .scan = dropbox_scan,
};

int br_dropbox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dropbox_fail(error, "invalid Dropbox detector output");
    *out = NULL;
    if (!dropbox_detector.state) {
        static const char *const extraction_keywords[] = {"dropbox"};
        br_regex *pattern = NULL;
        /* Dispatch has TWO keywords; extraction's PrefixRegex has ONLY one. */
        if (br_regex_compile_prefixed(extraction_keywords, 1,
                "\\b(sl\\.(u\\.)?[A-Za-z0-9\\-\\_]{130,})\\b", &pattern, error) != 0)
            return -1;
        dropbox_detector.state = pattern;
    }
    *out = &dropbox_detector;
    return 0;
}
