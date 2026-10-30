/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mrticktock/mrticktock.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *email, *password; } mrticktock_patterns;

/* Exact common.EmailPattern. Compiled directly, not prefixed. Group 1 is the address. */
static const char email_pattern[] = "\\b((?i)(?:[a-z0-9!#$%&'*+/=?^_\\x60{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_\\x60{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\]))\\b";

static int mrticktock_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Exact bytes only. Call this only for a reached body. */
static bool contains_errors(br_slice body)
{
    static const char needle[] = "\"errors\":[]";
    if (!body.data || body.len < sizeof(needle) - 1) return false;
    for (size_t i = 0; i + sizeof(needle) - 1 <= body.len; ++i)
        if (!memcmp(body.data + i, needle, sizeof(needle) - 1)) return true;
    return false;
}

/* Successful Do closes are scan-deferred. A stack body cannot survive that
 * release, so the original allocation stays with the response. The stack
 * header array is not retained. */
typedef struct mrticktock_pending mrticktock_pending;
struct mrticktock_pending {
    mrticktock_pending *next;
    br_http_response response;
    char *body;
};

static int mrticktock_retain(mrticktock_pending **pending, const br_http_response *response, char *body)
{
    mrticktock_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->body = body;
    *pending = item;
    return 0;
}

static void mrticktock_release_held(const br_scan_ctx *ctx, mrticktock_pending *pending)
{
    while (pending) {
        mrticktock_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->body);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. The complete raw body is owned before the
 * nil-context check. 1 drops this pair. 0 publishes it. Any other status,
 * including +1, is fatal. There is no setter. The password is not stored. */
static int mrticktock_verify(const br_scan_ctx *ctx, br_slice email, br_slice password,
                             br_result *result, mrticktock_pending **pending, char **error)
{
    if (email.len > SIZE_MAX - 17 || password.len > SIZE_MAX - 17 - email.len)
        return mrticktock_fail(error, "Mrticktock body too long");
    size_t n = 6 + email.len + 10 + password.len;
    char *body = malloc(n + 1);
    if (!body) return mrticktock_fail(error, "out of memory creating Mrticktock body");
    memcpy(body, "email=", 6);
    memcpy(body + 6, email.data, email.len);
    memcpy(body + 6 + email.len, "&password=", 10);
    memcpy(body + 6 + email.len + 10, password.data, password.len);
    body[n] = '\0';
    if (!ctx) {
        free(body);
        return 1;
    }
    /* The header array dies at send return. Do not retain it. */
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://mrticktock.com/app/api/is_timer_active",
        .headers = headers, .nheaders = 1, .body = {(const unsigned char *)body, n},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    /* Setup and Do errors stay unverified. Do not inspect the body or invent a cause. */
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(body);
        return 0;
    }
    if (mrticktock_retain(pending, &response, body) != 0) {
        br_http_release(ctx, &response);
        free(body);
        return mrticktock_fail(error, "cannot retain Mrticktock response for release");
    }
    /* ReadAll failure drops without a search. The response stays deferred. */
    if (response.body_error) return 1;
    if (!response.body.data && response.body.len)
        return mrticktock_fail(error, "invalid Mrticktock response body");
    /* Status alone is not enough. A missing needle stays unverified and is kept. */
    result->verified = response.status >= 200 && response.status < 300 &&
                       contains_errors(response.body);
    return 0;
}

static int mrticktock_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mrticktock_fail(error, "invalid or uninitialized Mrticktock scan");
    const mrticktock_patterns *patterns = detector->state;
    if (!patterns->email || !patterns->password)
        return mrticktock_fail(error, "uninitialized Mrticktock patterns");
    size_t original_len = out->len;
    br_captures emails = {0}, passwords = {0};
    mrticktock_pending *pending = NULL;
    char *owned_error = NULL;
    /* Email edges are non-whitespace, so TrimSpace is a no-op. Unique is
     * first-seen, not Go map order. Passwords keep every match, including
     * duplicates. Neither side alone yields a result. The password is hidden. */
    int rc = br_captures_find(patterns->email, input, &emails, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->password, input, &passwords, false, &owned_error);
    for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
        br_slice email = br_captures_at(&emails, e);
        for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
            br_result result = {0};
            br_slice password = br_captures_at(&passwords, p);
            bool keep = true;
            /* Finding resources precede body construction and the constructor skip. */
            if (br_finding_key_bytes(&result, detector->type, email, "key") != 0)
                rc = mrticktock_fail(&owned_error, "cannot create Mrticktock result");
            else if (verify) {
                int verdict = mrticktock_verify(ctx, email, password, &result, &pending, &owned_error);
                if (verdict == 1) keep = false;
                else if (verdict != 0) rc = -1;
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = mrticktock_fail(&owned_error, "cannot append Mrticktock result");
            br_result_clear(&result);
        }
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    mrticktock_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&passwords);
    br_captures_clear(&emails);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static mrticktock_patterns mrticktock_compiled;
static const char *const mrticktock_keywords[] = {"mrticktock"};
static const br_detector mrticktock_detector = {
    .type = 691, .version = 0, .name = "Mrticktock", .custom_name = "",
    .description = "Mrticktock is a service that tracks time-based activities. These credentials can be used to access and manage timers and associated data.",
    .keywords = mrticktock_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &mrticktock_compiled, .scan = mrticktock_scan,
};

int br_mrticktock_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mrticktock_fail(error, "invalid Mrticktock detector output");
    *out = NULL;
    if (!mrticktock_compiled.email &&
        br_regex_compile(email_pattern, &mrticktock_compiled.email, error) != 0)
        return -1;
    if (!mrticktock_compiled.password &&
        br_regex_compile_prefixed(mrticktock_keywords, 1,
                                  "\\b([a-zA-Z0-9!=@#$%()_^]{1,50})",
                                  &mrticktock_compiled.password, error) != 0)
        return -1;
    *out = &mrticktock_detector;
    return 0;
}
