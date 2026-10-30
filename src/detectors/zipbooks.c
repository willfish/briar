/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zipbooks/zipbooks.go. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const zipbooks_keywords[] = {"zipbooks"};

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int own_cause(char **cause, const char *message, char **error)
{
    if (!cause) return 0;
    *cause = strdup(message);
    if (!*cause) return fail(error, "cannot record ZipBooks verification error");
    return 0;
}

/* Body is built before NewRequestWithContext and stays alive through the one
 * release. A nil context is an ordinary constructor error, not a skipped setter. */
static int verify_zipbooks(const br_scan_ctx *ctx, const char *email, const char *password,
                           bool *verified, char **cause, char **error)
{
    *verified = false;
    if (cause) *cause = NULL;
    const char *fmt = "{\"email\": \"%s\", \"password\": \"%s\"}";
    size_t need = strlen(fmt) - 4 + strlen(email) + strlen(password) + 1;
    char *body = malloc(need);
    if (!body) return fail(error, "cannot create ZipBooks body");
    int n = snprintf(body, need, fmt, email, password);
    if (n < 0 || (size_t)n >= need) {
        free(body);
        return fail(error, "cannot format ZipBooks body");
    }
    if (!ctx) {
        int rc = own_cause(cause, "net/http: nil Context", error);
        free(body);
        return rc;
    }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.zipbooks.com/v2/auth/login",
        .headers = headers, .nheaders = 1, .body = {(const unsigned char *)body, (size_t)n},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 600,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        if (cause) *cause = send_error;
        else free(send_error);
        send_error = NULL;
    } else if (response.status == 200) *verified = true;
    else if (response.status != 401 && response.status != 404) {
        char message[64];
        int formatted = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = fail(error, "cannot format ZipBooks status");
        else rc = own_cause(cause, message, error);
    }
    br_http_release(ctx, &response);
    free(body);
    free(send_error);
    return rc;
}

static int scan_zipbooks(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ZipBooks scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures emails = {0}, passwords = {0};
    /* Email is the unprefixed common pattern, unique after TrimSpace. Both
     * classes exclude whitespace, so TrimSpace keeps the original capture. */
    int rc = br_captures_find(patterns[0], input, &emails, true, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &passwords, false, error);
    for (size_t i = 0; rc == 0 && i < emails.len; ++i) {
        for (size_t j = 0; rc == 0 && j < passwords.len; ++j) {
            br_result result = {0};
            br_slice email = br_captures_at(&emails, i);
            /* Raw is the email. The only secret part is literally "key". */
            if (br_finding_key_bytes(&result, detector->type, email, "key") != 0)
                rc = fail(error, "out of memory creating ZipBooks result");
            else if (verify) {
                bool verified = false;
                char *cause = NULL;
                if (verify_zipbooks(ctx, emails.items[i], passwords.items[j], &verified, &cause, error) != 0)
                    rc = -1;
                else {
                    result.verified = verified;
                    if (br_result_set_verification_error(&result, cause, &email, 1) != 0)
                        rc = fail(error, "cannot record ZipBooks verification error");
                }
                free(cause);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append ZipBooks result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&emails);
    br_captures_clear(&passwords);
    return rc == 0 ? 0 : -1;
}

static br_regex *zipbooks_patterns[2];
static br_detector zipbooks_detector = {
    .type = 600, .version = 0, .name = "ZipBooks", .custom_name = "",
    .description = "ZipBooks is an accounting software service that allows businesses to manage their finances online. The credentials can be used to access and manage financial data.",
    .keywords = zipbooks_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = zipbooks_patterns, .scan = scan_zipbooks,
};

int br_zipbooks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ZipBooks detector output");
    *out = NULL;
    if (!zipbooks_patterns[0] && br_regex_compile(br_email_pattern, &zipbooks_patterns[0], error) != 0)
        return -1;
    static const char *const password_keywords[] = {"zipbooks", "password"};
    if (!zipbooks_patterns[1] &&
        br_regex_compile_prefixed(password_keywords, 2, "\\b([a-zA-Z0-9!=@#$%^]{8,})",
                                  &zipbooks_patterns[1], error) != 0)
        return -1;
    *out = &zipbooks_detector;
    return 0;
}
