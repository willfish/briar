/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/instamojo/instamojo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *secret, *id; } instamojo_patterns;
enum { INSTAMOJO_SECRET_SIZE = 128, INSTAMOJO_ID_SIZE = 40 };

static int instamojo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int instamojo_status_cause(int status, char **cause, char **error)
{
    int needed = snprintf(NULL, 0, "unexpected HTTP response status %d", status);
    if (needed < 0) return instamojo_fail(error, "cannot format Instamojo status cause");
    *cause = malloc((size_t)needed + 1);
    if (!*cause) return instamojo_fail(error, "cannot allocate Instamojo status cause");
    if (snprintf(*cause, (size_t)needed + 1, "unexpected HTTP response status %d", status) != needed)
        return instamojo_fail(error, "cannot format Instamojo status cause");
    return 0;
}

/* ABI1 consumes the explicitly selected context transport. Do not infer a
 * client namespace or replace the source's optional/default SANE client. */
static int instamojo_verify_publish(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                                    br_result *result, br_results *out, char **error)
{
    static const char prefix[] = "grant_type=client_credentials&client_id=";
    static const char middle[] = "&client_secret=";
    const size_t form_size = sizeof(prefix) - 1 + INSTAMOJO_ID_SIZE +
                             sizeof(middle) - 1 + INSTAMOJO_SECRET_SIZE + 1;
    char *form = malloc(form_size);
    if (!form) return instamojo_fail(error, "cannot allocate Instamojo form");
    /* The alphanumeric captures need no encoding. The full literal form and
     * strings.Reader precede NewRequestWithContext's nil-context drop. */
    size_t at = sizeof(prefix) - 1;
    memcpy(form, prefix, at);
    memcpy(form + at, id.data, id.len); at += id.len;
    memcpy(form + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(form + at, secret.data, secret.len); at += secret.len;
    form[at] = '\0';
    const br_slice payload = {(const unsigned char *)form, at};
    if (!ctx) {
        free(form);
        return 0;
    }
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.instamojo.com/oauth2/token/",
        .headers = headers, .nheaders = 1, .body = payload,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *cause = NULL;
    int rc = 0;
    bool drop = false, set_error = false;
    if (br_http_send(ctx, &request, &response, &cause) != 0) {
        /* The whole mixed setup/Do domain is retained, regardless of sign or
         * diagnostic text. NULL is the setter's checked no-op, not a new cause. */
        set_error = true;
    } else if (response.body_error != NULL) {
        /* ReadAll runs at EVERY status; even an empty error drops this pair. */
        drop = true;
    } else if (!response.body.data && response.body.len) {
        rc = instamojo_fail(error, "unsupported: Instamojo invalid response body slice");
    } else {
        static const unsigned char marker[] = "access_token";
        if (response.status >= 200 && response.status < 300 &&
            br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX) {
            result->verified = true;
        } else {
            /* A successful 200 without the unquoted binary marker is also an
             * unexpected-status error. No JSON parsing or 401 special case. */
            rc = instamojo_status_cause(response.status, &cause, error);
            set_error = true;
        }
    }
    if (rc == 0 && set_error &&
        br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = instamojo_fail(error, "cannot set Instamojo verification error");
    if (rc == 0 && !drop && br_results_push(out, result) != 0)
        rc = instamojo_fail(error, "cannot append Instamojo finding");
    /* Source sets its verdict/error and appends before deferred Close. Preserve
     * that ordering, including on setter/format/push failure, with one ordinary
     * release per attempt. Form, original headers, captures and cause survive;
     * synthesized effective request/header-array/UA storage ends at send return.
     * Eager per-attempt release is not source deferred timing/leak parity. */
    br_http_release(ctx, &response);
    free(cause);
    free(form);
    return rc == 0 ? 0 : -1;
}

static int instamojo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return instamojo_fail(error, "invalid or uninitialized Instamojo scan");
    const instamojo_patterns *patterns = detector->state;
    if (!patterns->secret || !patterns->id)
        return instamojo_fail(error, "uninitialized Instamojo patterns");
    size_t original_len = out->len;
    br_captures secrets = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent secret-FIRST matching, then complete SECRET-major occurrence
     * products. TrimSpace cannot change these ASCII captures. Keep duplicates;
     * the 1024-byte engine hint is not a direct-scan pairing restriction. */
    for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
        br_slice secret = br_captures_at(&secrets, s);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            if (secret.len != INSTAMOJO_SECRET_SIZE || id.len != INSTAMOJO_ID_SIZE)
                rc = instamojo_fail(&owned_error, "invalid Instamojo capture");
            else if (br_finding_key_bytes(&result, detector->type, id, "key") != 0)
                rc = instamojo_fail(&owned_error, "cannot create Instamojo finding");
            if (rc == 0) {
                if (verify) rc = instamojo_verify_publish(ctx, id, secret, &result, out, &owned_error);
                else if (br_results_push(out, &result) != 0)
                    rc = instamojo_fail(&owned_error, "cannot append Instamojo finding");
            }
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

static instamojo_patterns instamojo_compiled;
static const char *const instamojo_keywords[] = {"instamojo"};
static const br_detector instamojo_detector = {
    .type = 941, .version = 0, .name = "Instamojo", .custom_name = "",
    .description = "An Ecommerce service, API keys can be used to create and access customer data",
    .keywords = instamojo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &instamojo_compiled, .scan = instamojo_scan,
};

int br_instamojo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return instamojo_fail(error, "invalid Instamojo detector output");
    *out = NULL;
    if (!instamojo_compiled.secret && br_regex_compile_prefixed(instamojo_keywords, 1,
            "\\b([0-9a-zA-Z]{128})\\b", &instamojo_compiled.secret, error) != 0) return -1;
    if (!instamojo_compiled.id && br_regex_compile_prefixed(instamojo_keywords, 1,
            "\\b([0-9a-zA-Z]{40})\\b", &instamojo_compiled.id, error) != 0) return -1;
    *out = &instamojo_detector;
    return 0;
}
