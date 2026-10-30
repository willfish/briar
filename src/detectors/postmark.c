/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/postmark/postmark.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char postmark_capture[] =
    "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b";
static const char postmark_nil_context[] = "net/http: nil Context";
static const char postmark_server_url[] = "https://api.postmarkapp.com/deliverystats";
static const char postmark_account_url[] = "https://api.postmarkapp.com/domains?count=10&offset=0";

static int postmark_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int postmark_status(int status, char **out, char **error)
{
    char buf[48];
    /* Every count other than the complete message is owned failure, including +1. */
    int n = snprintf(NULL, 0, "unexpected status code: %d", status);
    if (n < 0 || n >= (int)sizeof(buf)) return postmark_fail(error, "cannot format Postmark status");
    int m = snprintf(buf, sizeof(buf), "unexpected status code: %d", status);
    if (m != n) return postmark_fail(error, "cannot format Postmark status");
    char *text = malloc((size_t)m + 1);
    if (!text) return postmark_fail(error, "cannot allocate Postmark status");
    memcpy(text, buf, (size_t)m + 1);
    *out = text;
    return 0;
}

static int postmark_attempt(const br_scan_ctx *ctx, const char *url, const char *header,
                            const char *token, bool *valid, const char **cause, bool *owned, char **error)
{
    *valid = false;
    *cause = NULL;
    *owned = false;
    /* Both nil constructors fail before any send. This is not a finding drop. */
    if (!ctx) {
        *cause = postmark_nil_context;
        return 0;
    }
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Content-Type", "application/json"},
        {header, token},
    };
    br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 81,
    };
    br_http_response response = {0};
    char *send_error = NULL, *status_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        /* A missing leaf is a nil error, not a fabricated diagnostic. Status is ignored. */
        *cause = send_error;
        *owned = send_error != NULL;
    } else if (response.status == 200) {
        *valid = true;
    } else if (response.status != 401) {
        rc = postmark_status(response.status, &status_error, error);
        *cause = status_error;
        *owned = rc == 0;
    }
    /* Body bytes and body_error never join. Release this attempt before the next call. */
    br_http_release(ctx, &response);
    return rc;
}

static int postmark_extra(br_result *result, const char *type, char **error)
{
    br_json *extra = json_object_new_object();
    if (!extra) return postmark_fail(error, "cannot allocate Postmark extra data");
    br_json *value = json_object_new_string(type);
    if (!value) {
        json_object_put(extra);
        return postmark_fail(error, "cannot allocate Postmark type");
    }
    if (json_object_object_add(extra, "type", value) != 0) {
        json_object_put(value);
        json_object_put(extra);
        return postmark_fail(error, "cannot add Postmark type");
    }
    result->extra_data = extra;
    result->verified = true;
    return 0;
}

static int postmark_apply_error(br_result *result, const char *server, bool server_owned,
                                const char *account, bool account_owned, char **error)
{
    char *joined = NULL;
    const char *text = NULL;
    int rc = 0;
    if (server && account) {
        /* errors.Join implements Unwrap() []error, so unwrap-to-last does not peel it.
         * Store both texts with one newline, server first. Do not redact the key. */
        size_t a = strlen(server), b = strlen(account);
        if (a > SIZE_MAX - b - 2) rc = postmark_fail(error, "Postmark verification error too large");
        else if (!(joined = malloc(a + b + 2))) rc = postmark_fail(error, "cannot join Postmark verification errors");
        else {
            memcpy(joined, server, a);
            joined[a] = '\n';
            memcpy(joined + a + 1, account, b + 1);
            text = joined;
        }
    } else if (server || account) {
        text = server ? server : account;
    }
    if (rc == 0 && text && br_result_set_verification_error(result, text, NULL, 0) != 0)
        rc = postmark_fail(error, "cannot set Postmark verification error");
    free(joined);
    if (server_owned) free((char *)server);
    if (account_owned) free((char *)account);
    return rc;
}

static int postmark_verify(const br_scan_ctx *ctx, const char *token, br_result *result, char **error)
{
    bool server_ok = false, account_ok = false;
    const char *server_err = NULL, *account_err = NULL;
    bool server_owned = false, account_owned = false;
    int rc = postmark_attempt(ctx, postmark_server_url, "X-Postmark-Server-Token", token,
                              &server_ok, &server_err, &server_owned, error);
    if (rc == 0 && server_ok) {
        /* Exact 200 returns immediately. Account is not called and no setter runs. */
        rc = postmark_extra(result, "server", error);
    } else if (rc == 0) {
        /* 401 and every server error still try the account endpoint. */
        rc = postmark_attempt(ctx, postmark_account_url, "X-Postmark-Account-Token", token,
                              &account_ok, &account_err, &account_owned, error);
        if (rc == 0 && account_ok) {
            if (server_owned) free((char *)server_err);
            server_err = NULL;
            server_owned = false;
            rc = postmark_extra(result, "account", error);
        } else if (rc == 0) {
            rc = postmark_apply_error(result, server_err, server_owned, account_err, account_owned, error);
            server_err = account_err = NULL;
            server_owned = account_owned = false;
        }
    }
    if (server_owned) free((char *)server_err);
    if (account_owned) free((char *)account_err);
    return rc;
}

static int postmark_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return postmark_fail(error, "invalid or uninitialized Postmark scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Prefixed keyword, not a raw regex. Occurrences stay in order; do not unique them.
     * The capture class makes source TrimSpace a no-op. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        char token[37];
        if (key.len != 36 || !key.data || memchr(key.data, 0, key.len))
            rc = postmark_fail(&owned_error, "invalid Postmark key capture");
        else {
            memcpy(token, key.data, 36);
            token[36] = '\0';
        }
        if (rc == 0 && br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = postmark_fail(&owned_error, "cannot create Postmark finding");
        if (rc == 0 && verify) rc = postmark_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = postmark_fail(&owned_error, "cannot append Postmark finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        postmark_fail(&owned_error, "cannot collect Postmark credentials");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const postmark_keywords[] = {"postmark"};
static br_detector postmark_detector = {
    .type = 81, .version = 0, .name = "Postmark", .custom_name = "",
    .description = "Postmark is an email delivery service. Postmark server tokens can be used to access and manage email delivery and statistics.",
    .keywords = postmark_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = postmark_scan,
};

int br_postmark_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return postmark_fail(error, "invalid Postmark detector output");
    *out = NULL;
    if (!postmark_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(postmark_keywords, 1, postmark_capture, &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        postmark_detector.state = pattern;
    }
    *out = &postmark_detector;
    return 0;
}
