/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rev/rev.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *user, *client; } rev_patterns;
typedef enum { REV_ABORT = -1, REV_KEEP = 0, REV_DROP = 1 } rev_outcome;

static int rev_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int rev_collect(const br_regex *pattern, br_slice input, size_t trimmed,
                       char ***out, size_t *count, char **error)
{
    *out = NULL;
    *count = 0;
    br_captures found = {0};
    int rc = br_captures_find(pattern, input, &found, false, error);
    if (rc != 0) return -1;
    if (!found.len) { br_captures_clear(&found); return 0; }
    char **items = calloc(found.len, sizeof(*items));
    if (!items) {
        br_captures_clear(&found);
        return rev_fail(error, "out of memory collecting Rev captures");
    }
    for (size_t i = 0; rc == 0 && i < found.len; ++i) {
        br_slice raw = br_captures_at(&found, i);
        /* The required terminator is inside the capture. TrimSpace removes it. */
        if (raw.len != trimmed + 1 || !raw.data ||
            (raw.data[trimmed] != ' ' && raw.data[trimmed] != '\r' && raw.data[trimmed] != '\n'))
            rc = rev_fail(error, "unexpected Rev capture shape");
        else {
            items[i] = malloc(trimmed + 1);
            if (!items[i]) rc = rev_fail(error, "out of memory copying Rev capture");
            else {
                memcpy(items[i], raw.data, trimmed);
                items[i][trimmed] = '\0';
            }
        }
    }
    size_t n = found.len;
    br_captures_clear(&found);
    if (rc != 0) {
        for (size_t i = 0; i < n; ++i) free(items[i]);
        free(items);
        return -1;
    }
    *out = items;
    *count = n;
    return 0;
}

static rev_outcome rev_verify(const br_scan_ctx *ctx, const char *client, const char *user,
                              br_result *result, char **error)
{
    /* Static URL. A nil context fails NewRequestWithContext before Header.Add. */
    if (!ctx) return REV_DROP;
    if (strlen(client) != 27 || strlen(user) != 28)
        return rev_fail(error, "unexpected Rev credential length"), REV_ABORT;
    char authorization[61];
    memcpy(authorization, "Rev ", 4);
    memcpy(authorization + 4, client, 27);
    authorization[31] = ':';
    memcpy(authorization + 32, user, 28);
    authorization[60] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.rev.com/api/v1/orders",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return REV_KEEP;
}

static int rev_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return rev_fail(error, "invalid or uninitialized Rev scan");
    const rev_patterns *patterns = detector->state;
    size_t original_len = out->len;
    char **users = NULL, **clients = NULL;
    size_t nusers = 0, nclients = 0;
    char *owned_error = NULL;
    int rc = rev_collect(patterns->user, input, 28, &users, &nusers, &owned_error);
    if (rc == 0) rc = rev_collect(patterns->client, input, 27, &clients, &nclients, &owned_error);
    for (size_t u = 0; rc == 0 && u < nusers; ++u) {
        for (size_t c = 0; rc == 0 && c < nclients; ++c) {
            br_result result = {0};
            rev_outcome outcome = REV_KEEP;
            if (br_finding_pair(&result, detector->type, users[u], "key", clients[c], "client") != 0)
                rc = rev_fail(&owned_error, "cannot create Rev result");
            else {
                /* Go leaves RawV2 empty. Pair helper concatenation is not part of the result. */
                free(result.raw_v2.data);
                result.raw_v2.data = NULL;
                result.raw_v2.len = 0;
                if (verify) outcome = rev_verify(ctx, clients[c], users[u], &result, &owned_error);
            }
            if (rc == 0 && outcome == REV_ABORT) rc = -1;
            if (rc == 0 && outcome == REV_KEEP && br_results_push(out, &result) != 0)
                rc = rev_fail(&owned_error, "cannot append Rev result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < nusers; ++i) free(users[i]);
    for (size_t i = 0; i < nclients; ++i) free(clients[i]);
    free(users);
    free(clients);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rev_keywords[] = {"rev"};
static rev_patterns rev_state;
static br_detector rev_detector = {
    .type = 368, .version = 0, .name = "Rev", .custom_name = "",
    .description = "Rev is a transcription service. Rev API keys can be used to access and modify transcription orders and data.",
    .keywords = rev_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = rev_scan, .state = &rev_state,
};

int br_rev_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rev_fail(error, "invalid Rev detector output");
    *out = NULL;
    if (!rev_state.user &&
        br_regex_compile_prefixed(rev_keywords, 1, "\\b([0-9a-zA-Z\\/\\+]{27}\\=[ \\r\\n]{1})",
                                  &rev_state.user, error) != 0)
        return -1;
    if (!rev_state.client &&
        br_regex_compile_prefixed(rev_keywords, 1, "\\b([0-9a-zA-Z\\-]{27}[ \\r\\n]{1})",
                                  &rev_state.client, error) != 0)
        return -1;
    *out = &rev_detector;
    return 0;
}
