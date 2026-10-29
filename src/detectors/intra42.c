/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/intra42/intra42.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *secret, *id; } intra42_patterns;
enum { INTRA42_TOKEN_SIZE = 73 };

static int intra42_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int intra42_status_cause(int status, char **cause, char **error)
{
    int needed = snprintf(NULL, 0, "unexpected http response status %d", status);
    if (needed < 0) return intra42_fail(error, "cannot format Intra42 status cause");
    *cause = malloc((size_t)needed + 1);
    if (!*cause) return intra42_fail(error, "cannot allocate Intra42 status cause");
    if (snprintf(*cause, (size_t)needed + 1, "unexpected http response status %d", status) != needed)
        return intra42_fail(error, "cannot format Intra42 status cause");
    return 0;
}

static int intra42_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                           bool *verified, char **cause, char **error)
{
    static const char prefix[] = "client_id=";
    static const char middle[] = "&client_secret=";
    static const char suffix[] = "&grant_type=client_credentials";
    const size_t form_size = sizeof(prefix) - 1 + INTRA42_TOKEN_SIZE +
                             sizeof(middle) - 1 + INTRA42_TOKEN_SIZE + sizeof(suffix);
    *verified = false;
    *cause = NULL;
    char *form = malloc(form_size);
    if (!form) return intra42_fail(error, "cannot allocate Intra42 form");
    /* url.Values.Encode sorts these keys. All captured/fixed bytes are
     * unreserved, so this is the complete encoded form, before construction. */
    size_t at = sizeof(prefix) - 1;
    memcpy(form, prefix, at);
    memcpy(form + at, id.data, id.len); at += id.len;
    memcpy(form + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(form + at, secret.data, secret.len); at += secret.len;
    memcpy(form + at, suffix, sizeof(suffix)); at += sizeof(suffix) - 1;
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        free(form);
        return *cause ? 0 : intra42_fail(error, "cannot allocate Intra42 constructor cause");
    }
    /* The second source Encode supplies only the decimal length; it does not
     * mutate the reader's body. Header additions follow successful construction. */
    char length[3 * sizeof(size_t) + 1];
    int digits = snprintf(length, sizeof(length), "%zu", at);
    if (digits < 0 || (size_t)digits >= sizeof(length)) {
        free(form);
        return intra42_fail(error, "cannot format Intra42 content length");
    }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Content-Length", length},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.intra.42.fr/oauth/token",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)form, at},
        .profile = BR_HTTP_SANE, .detector_type = 987,
    };
    br_http_response response = {0};
    int rc = 0;
    bool verdict = false;
    /* Retain the entire mixed shared setup/Do error domain, without interpreting
     * diagnostic text or return-code sign. Bodies/read errors are never read. */
    if (br_http_send(ctx, &request, &response, cause) == 0) {
        if (response.status == 200) verdict = true;
        else if (response.status != 401)
            rc = intra42_status_cause(response.status, cause, error);
    }
    /* The source helper closes before its caller sets Verified and invokes the
     * setter. Release once even after failed preparation or owned formatting.
     * Form, original headers/length, captures and cause live through release;
     * shared effective request/header-array/UA storage ends at send return. */
    br_http_release(ctx, &response);
    free(form);
    if (rc != 0) return -1;
    *verified = verdict;
    return 0;
}

static int intra42_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return intra42_fail(error, "invalid or uninitialized Intra42 scan");
    const intra42_patterns *patterns = detector->state;
    if (!patterns->secret || !patterns->id)
        return intra42_fail(error, "uninitialized Intra42 patterns");
    size_t original_len = out->len;
    br_captures secrets = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent secret-FIRST collection, then secret-major occurrence products.
     * TrimSpace is a no-op; keep duplicates and cross-flavor pairs. The engine's
     * span1024 hint is not a direct-scan distance restriction. */
    for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
        br_slice secret = br_captures_at(&secrets, s);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            if (secret.len != INTRA42_TOKEN_SIZE || id.len != INTRA42_TOKEN_SIZE)
                rc = intra42_fail(&owned_error, "invalid Intra42 capture");
            else if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
                rc = intra42_fail(&owned_error, "cannot create Intra42 finding");
            if (rc == 0 && verify) {
                bool verified = false;
                char *cause = NULL;
                rc = intra42_verify(ctx, id, secret, &verified, &cause, &owned_error);
                if (rc == 0) {
                    result.verified = verified;
                    /* Mandatory even for NULL: the shared setter is a checked
                     * no-op, and every nonzero (including +1) is fatal. */
                    if (br_result_set_verification_error(&result, cause, &secret, 1) != 0)
                        rc = intra42_fail(&owned_error, "cannot set Intra42 verification error");
                }
                free(cause);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = intra42_fail(&owned_error, "cannot append Intra42 finding");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static intra42_patterns intra42_compiled;
static const char *const intra42_keywords[] = {"s-s4t2ud-", "s-s4t2af-"};
static const br_detector intra42_detector = {
    .type = 987, .version = 0, .name = "Intra42", .custom_name = "",
    .description = "Intra42 is an API service used to interact with the 42 school's internal systems. Intra42 API keys can be used to access and modify data within these systems.",
    .keywords = intra42_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &intra42_compiled, .scan = intra42_scan,
};

int br_intra42_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return intra42_fail(error, "invalid Intra42 detector output");
    *out = NULL;
    if (!intra42_compiled.secret && br_regex_compile("\\b(s-s4t2(?:ud|af)-[a-f0-9]{64})\\b",
            &intra42_compiled.secret, error) != 0) return -1;
    if (!intra42_compiled.id && br_regex_compile("\\b(u-s4t2(?:ud|af)-[a-f0-9]{64})\\b",
            &intra42_compiled.id, error) != 0) return -1;
    *out = &intra42_detector;
    return 0;
}
