/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dotdigital/dotdigital.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *email, *password; } dotdigital_patterns;

static int dotdigital_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int dotdigital_verify(const br_scan_ctx *ctx, br_slice email, br_slice password,
                             br_result *result, char **error)
{
    /* Source selects its client and assigns Timeout=10s BEFORE construction.
     * ABI1 uses a per-request timeout, not a shared/global client mutation.
     * Constructor failure RETAINS this pair, before any Basic encoding. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return dotdigital_fail(error, "cannot set Dotdigital verification error");
        return 0;
    }
    char *authorization = NULL;
    if (br_http_basic_auth(email, password, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://r1-api.dotdigital.com/v2/account-info",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .timeout_ms = 10000, .detector_type = result->detector_type,
        /* http.NoBody is represented by an empty body, not a payload. */
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* Retain the entire mixed shared setup/allocation/Do domain as an ordinary
     * leaf cause. Never classify, strip text, or supply redaction secrets. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = dotdigital_fail(error, "cannot format Dotdigital status error");
        else cause = status_error;
    }
    /* Source drains/closes AFTER status, before its caller sets the error.
     * Borrow the complete owned Basic value through BOTH send and release.
     * Body/read errors do not affect the decision. Eager buffering/release,
     * private-client mutation/races, NoBody/Reader lifecycle, full SANE/RE2
     * and global engine/output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(authorization);
    /* NULL cause is deliberately passed: the shared setter is a no-op for it.
     * Every nonzero setter result is fatal, including its positive failures. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = dotdigital_fail(error, "cannot set Dotdigital verification error");
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int dotdigital_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dotdigital_fail(error, "invalid or uninitialized Dotdigital scan");
    const dotdigital_patterns *patterns = detector->state;
    if (!patterns->email || !patterns->password)
        return dotdigital_fail(error, "uninitialized Dotdigital patterns");
    size_t original_len = out->len;
    br_captures emails = {0}, passwords = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->email, input, &emails, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->password, input, &passwords, true, &owned_error);
    /* Independent byte-original uniqueness, without trimming. Native sets use
     * first-occurrence order; upstream map order is unspecified. No local span,
     * equality or entropy check restricts the email-major Cartesian product. */
    for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
        br_slice email = br_captures_at(&emails, e);
        for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
            br_result result = {0};
            br_slice password = br_captures_at(&passwords, p);
            /* Each pair owns fresh parts and RawV2 before any verification. */
            if (br_finding_pair_bytes(&result, detector->type, email, "email",
                                      password, "password", (br_slice){0}) != 0)
                rc = dotdigital_fail(&owned_error, "cannot create Dotdigital result");
            if (rc == 0 && verify)
                rc = dotdigital_verify(ctx, email, password, &result, &owned_error);
            bool verified = result.verified;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = dotdigital_fail(&owned_error, "cannot append Dotdigital result");
            br_result_clear(&result);
            if (rc == 0 && verified) break; /* Only this email's password loop, AFTER append. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&passwords);
    br_captures_clear(&emails);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static dotdigital_patterns dotdigital_compiled;
static const char *const dotdigital_keywords[] = {"@apiconnector.com"};
static const br_detector dotdigital_detector = {
    .type = 325, .version = 0, .name = "Dotdigital", .custom_name = "",
    .description = "Dotdigital is an email marketing automation platform. API keys can be used to access and manage email campaigns and related data.",
    .keywords = dotdigital_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &dotdigital_compiled, .scan = dotdigital_scan,
};

int br_dotdigital_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dotdigital_fail(error, "invalid Dotdigital detector output");
    *out = NULL;
    /* Preserve the source's unescaped dot, not an invented email validator. */
    if (!dotdigital_compiled.email && br_regex_compile(
            "\\b(apiuser-[a-z0-9]{12}@apiconnector.com)\\b", &dotdigital_compiled.email, error) != 0)
        return -1;
    static const char *const password_keywords[] = {"pw", "pass"};
    /* [a-zA-Z0-9\\S] equals RE2's complement of FIVE ASCII whitespace runes.
     * PCRE2's \\S would wrongly exclude VT. This private class also retains
     * Unicode, embedded NUL and punctuation, with the source word boundaries. */
    if (!dotdigital_compiled.password && br_regex_compile_prefixed(password_keywords, 2,
            "\\b([^\\t\\n\\f\\r ]{8,24})\\b", &dotdigital_compiled.password, error) != 0)
        return -1;
    *out = &dotdigital_detector;
    return 0;
}
