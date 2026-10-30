/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/replyio/replyio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

/* A nil context is a constructor error and drops this candidate before append.
 * Other failures still append. Close is deferred in Go; release is required
 * after every send and happens before the match buffer dies. */
static int verify_replyio(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx) return 1;
    const br_header headers[] = {{"X-Api-Key", (const char *)secret.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.reply.io/v1/people",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 956,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    bool error_present = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* Do failure is present even when the diagnostic is NULL. */
        error_present = true;
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format ReplyIO status");
        else {
            error_present = true;
            cause = status_error;
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = -1; /* Fatal even when the diagnostic cannot be stored. */
    free(send_error);
    return rc;
}

static int scan_replyio(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ReplyIO scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create ReplyIO finding");
        } else if (verify) {
            int status = verify_replyio(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue; /* Constructor error drops only this candidate. */
            }
            if (status < 0) rc = -1; /* Fatal is not an ordinary skip. */
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ReplyIO finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"replyio"};
static br_detector replyio = {
    .type = 956, .version = 0, .name = "ReplyIO", .custom_name = "",
    .description = "Reply.io is a sales engagement platform used for automating communication with prospects. The API key can be used to access and manage communication data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_replyio,
};

int br_replyio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ReplyIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&replyio, "\\b([0-9A-Za-z]{24})\\b", error) != 0) return -1;
    *out = &replyio;
    return 0;
}
