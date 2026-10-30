/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/salesforce/salesforce.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

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

/* bufio.Scanner lines, default 64KiB token. "records" must sit on one line. */
static int contains_records(br_slice body, const char **scan_error)
{
    *scan_error = NULL;
    size_t at = 0;
    while (at < body.len) {
        size_t start = at, end = at;
        while (end < body.len && body.data[end] != '\n') ++end;
        size_t line = end - start;
        bool more = end < body.len;
        if (line && body.data[start + line - 1] == '\r') --line;
        if (line > 64 * 1024 || (!more && line > 64 * 1024)) {
            *scan_error = "bufio.Scanner: token too long";
            return 0;
        }
        if (!more && end - start > 64 * 1024) {
            *scan_error = "bufio.Scanner: token too long";
            return 0;
        }
        if (line > 64 * 1024) {
            *scan_error = "bufio.Scanner: token too long";
            return 0;
        }
        if (br_slice_find((br_slice){body.data + start, line},
                          (br_slice){(const unsigned char *)"records", 7}, 0) != SIZE_MAX)
            return 1;
        if (!more) break;
        at = end + 1;
        if (end - start > 64 * 1024) {
            *scan_error = "bufio.Scanner: token too long";
            return 0;
        }
    }
    return 0;
}

static int verify_salesforce(const br_scan_ctx *ctx, br_slice token, const char *url,
                             br_result *result, char **error)
{
    if (!ctx) return 1;
    char auth[8 + 112 + 1];
    if (token.len > 112) return fail(error, "invalid Salesforce token");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, token.data, token.len);
    auth[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000, .detector_type = 925,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[512];
    const char *cause = NULL;
    bool error_present = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        error_present = true;
        cause = send_error;
    } else {
        const char *scan_error = response.body_error;
        int found = scan_error ? 0 : contains_records(response.body, &scan_error);
        if (response.status >= 200 && response.status < 300) {
            result->verified = found && !scan_error;
        } else if (response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error),
                             "request to %s returned status %d with error %s",
                             url, response.status, scan_error ? scan_error : "<nil>");
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = fail(error, "cannot format Salesforce status");
            else {
                error_present = true;
                cause = status_error;
            }
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = -1;
    free(send_error);
    return rc;
}

typedef struct { br_regex *token, *instance; } salesforce_state;

static int scan_salesforce(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    salesforce_state *state = detector ? (salesforce_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Salesforce scan");
    size_t before = out->len;
    br_captures tokens = {0}, instances = {0};
    char *owned = NULL;
    int rc = br_captures_find(state->instance, input, &instances, false, &owned);
    if (!rc) rc = br_captures_find(state->token, input, &tokens, false, &owned);
    for (size_t i = 0; !rc && i < instances.len; ++i) {
        br_slice instance = br_captures_at(&instances, i);
        char url[256];
        int n = snprintf(url, sizeof(url), "%.*s/services/data/v58.0/query?q=SELECT+name+from+Account",
                         (int)instance.len, (const char *)instance.data);
        if (n < 0 || (size_t)n >= sizeof(url)) {
            rc = fail(&owned, "cannot format Salesforce URL");
            break;
        }
        for (size_t j = 0; !rc && j < tokens.len; ++j) {
            br_slice token = br_captures_at(&tokens, j);
            if (verify && !ctx) continue;
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                rc = fail(&owned, "cannot create Salesforce finding");
            else if (verify && verify_salesforce(ctx, token, url, &result, &owned) != 0)
                rc = -1;
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Salesforce finding");
            br_result_clear(&result);
        }
    }
    if (rc) rollback(out, before);
    br_captures_clear(&tokens);
    br_captures_clear(&instances);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"salesforce"};
static br_detector salesforce = {
    .type = 925, .version = 0, .name = "Salesforce", .custom_name = "",
    .description = "Salesforce is a cloud-based software company that provides customer relationship management (CRM) service. Salesforce access tokens can be used to authenticate and interact with Salesforce APIs.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_salesforce,
};

int br_salesforce_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Salesforce detector output");
    *out = NULL;
    if (salesforce.state) { *out = &salesforce; return 0; }
    salesforce_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Salesforce patterns");
    if (br_regex_compile("(\\b00[a-zA-Z0-9]{13}![a-zA-Z0-9_.]{96}\\b)", &state->token, error) != 0 ||
        br_regex_compile("(\\bhttps://[0-9a-zA-Z\\-\\.]{1,100}\\.my\\.salesforce\\.com\\b)",
                         &state->instance, error) != 0) {
        free(state);
        return -1;
    }
    salesforce.state = state;
    *out = &salesforce;
    return 0;
}
