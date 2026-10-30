/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/slackwebhook/slackwebhook.go.
 * The source map has no iteration order; service hooks are scanned first. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *service, *workflow; } slack_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int rotation(br_result *result)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/slack-webhook/");
    if (!result->extra_data || !guide || json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return -1;
    }
    return 0;
}

static int verify_slack(const br_scan_ctx *ctx, const char *url, br_result *result, bool *drop, char **error)
{
    *drop = false;
    if (!ctx) return 1;
    static const unsigned char payload[] = "intentionally malformed JSON from TruffleHog scan";
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 30,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char *owned_cause = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error;
    else if (response.body_error) *drop = true;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status == 400 && response.body.len == sizeof("invalid_payload") - 1 &&
             response.body.data && !memcmp(response.body.data, "invalid_payload", response.body.len))
        result->verified = true;
    else if (response.status == 400 &&
             br_slice_find(response.body, (br_slice){(const unsigned char *)"invalid_token", 13}, 0) != SIZE_MAX) {
        /* Revoked webhook: determinate and unverified. */
    } else if (response.status == 404 || response.status == 403) {
        /* Missing webhook or revoked app: determinate and unverified. */
    } else {
        size_t prefix = (size_t)snprintf(NULL, 0, "unexpected HTTP response status %d: ", response.status);
        owned_cause = malloc(prefix + response.body.len + 1);
        if (!owned_cause) {
            br_http_release(ctx, &response);
            free(send_error);
            return fail(error, "out of memory recording SlackWebhook status");
        }
        snprintf(owned_cause, prefix + 1, "unexpected HTTP response status %d: ", response.status);
        if (response.body.len && response.body.data) memcpy(owned_cause + prefix, response.body.data, response.body.len);
        owned_cause[prefix + response.body.len] = 0;
        if (response.body.data && memchr(response.body.data, 0, response.body.len)) {
            free(owned_cause);
            br_http_release(ctx, &response);
            free(send_error);
            return fail(error, "unsupported: SlackWebhook binary status body");
        }
        cause = owned_cause;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = 0;
    if (!*drop && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "out of memory recording SlackWebhook verification error");
    br_http_release(ctx, &response);
    free(send_error);
    free(owned_cause);
    return rc;
}

static int scan_one(const br_regex *pattern, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    br_captures hooks = {0};
    int rc = br_captures_find(pattern, input, &hooks, false, error);
    for (size_t i = 0; !rc && i < hooks.len; ++i) {
        br_result result = {0};
        bool drop = false;
        if (br_finding_key(&result, 30, hooks.items[i], "key") != 0 || rotation(&result) != 0)
            rc = fail(error, "out of memory creating SlackWebhook result");
        else if (verify && verify_slack(ctx, hooks.items[i], &result, &drop, error) > 0) {
            br_result_clear(&result);
            continue;
        } else if (verify && *error) rc = -1;
        if (!rc && !drop && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending SlackWebhook result");
        br_result_clear(&result);
    }
    br_captures_clear(&hooks);
    return rc;
}

static int scan_slack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SlackWebhook scan");
    const slack_patterns *patterns = detector->state;
    size_t original_len = out->len;
    char *owned = NULL;
    int rc = scan_one(patterns->service, ctx, verify, input, out, &owned);
    if (!rc) rc = scan_one(patterns->workflow, ctx, verify, input, out, &owned);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static bool slack_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    if (reason) *reason = NULL;
    if (!result) return false;
    static const unsigned char marker[] = "https:";
    if (br_slice_find((br_slice){result->raw.data, result->raw.len}, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX)
        return false;
    static const char *const terms[] = {"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"};
    return br_known_false_positive((br_slice){result->raw.data, result->raw.len}, terms, 7, true, reason);
}

static const char *const keywords[] = {"hooks.slack.com"};
static slack_patterns patterns;
static br_detector slackwebhook = {
    .type = 30, .version = 0, .name = "SlackWebhook", .custom_name = "",
    .description = "Slack webhooks are used to send messages from external sources into Slack channels. If compromised, they can be used to send unauthorized messages.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_slack, .false_positive = slack_false_positive,
};

int br_slackwebhook_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SlackWebhook detector output");
    *out = NULL;
    if (!patterns.service && br_regex_compile("(https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25})", &patterns.service, error) != 0)
        return -1;
    if (!patterns.workflow && br_regex_compile("(https://hooks\\.slack\\.com/workflows/T[A-Z0-9]+/A[A-Z0-9]+/[0-9]{17,19}/[A-Za-z0-9]{23,25})", &patterns.workflow, error) != 0)
        return -1;
    *out = &slackwebhook;
    return 0;
}
