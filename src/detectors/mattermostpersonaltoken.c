/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mattermostpersonaltoken. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum { MM_ABORT = -1, MM_KEEP = 0, MM_DROP = 1 } mm_outcome;
typedef struct { br_regex *key, *server; } mm_patterns;

static int mm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static char *mm_url(br_slice server, char **error)
{
    static const char prefix[] = "https://", suffix[] = "/api/v4/users/stats";
    if (server.len > SIZE_MAX - (sizeof(prefix) + sizeof(suffix))) {
        mm_fail(error, "MattermostPersonalToken URL size overflow");
        return NULL;
    }
    /* {1,} is unbounded and the unescaped dots are any byte. Own the URL. */
    char *url = malloc(sizeof(prefix) - 1 + server.len + sizeof(suffix));
    if (!url) {
        mm_fail(error, "cannot allocate MattermostPersonalToken URL");
        return NULL;
    }
    memcpy(url, prefix, sizeof(prefix) - 1);
    if (server.len) memcpy(url + sizeof(prefix) - 1, server.data, server.len);
    memcpy(url + sizeof(prefix) - 1 + server.len, suffix, sizeof(suffix));
    return url;
}

static mm_outcome mm_verify(const br_scan_ctx *ctx, br_slice key, br_slice server,
                            br_result *result, char **error)
{
    char *url = mm_url(server, error);
    if (!url) return MM_ABORT;
    /* Argument evaluation builds the URL before NewRequestWithContext. A nil
     * context continues, discarding this pair, and never adds Authorization. */
    if (!ctx) {
        free(url);
        return MM_DROP;
    }
    if (key.len > SIZE_MAX - 8) {
        free(url);
        mm_fail(error, "MattermostPersonalToken authorization size overflow");
        return MM_ABORT;
    }
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization) {
        free(url);
        mm_fail(error, "cannot allocate MattermostPersonalToken authorization");
        return MM_ABORT;
    }
    memcpy(authorization, "Bearer ", 7);
    if (key.len) memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Do and status failures stay unverified. No setter. Body and read errors
     * are ignored. Authorization and the owned URL live through release. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    free(url);
    return MM_KEEP;
}

static int mm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mm_fail(error, "invalid or uninitialized MattermostPersonalToken scan");
    const mm_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->server)
        return mm_fail(error, "uninitialized MattermostPersonalToken patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, servers = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->server, input, &servers, false, &owned_error);
    /* Keep every key-major/server-minor pair, including duplicates. Both
     * captures exclude leading and trailing whitespace, so TrimSpace is a no-op.
     * A missing server yields no finding; there is no host fallback. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t s = 0; rc == 0 && s < servers.len; ++s) {
            br_result result = {0};
            mm_outcome outcome = MM_KEEP;
            br_slice server = br_captures_at(&servers, s);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", server, "url",
                                      (br_slice){0}) != 0)
                rc = mm_fail(&owned_error, "cannot create MattermostPersonalToken result");
            else if (verify)
                outcome = mm_verify(ctx, key, server, &result, &owned_error);
            if (rc == 0 && outcome == MM_ABORT) rc = -1;
            if (rc == 0 && outcome == MM_KEEP && br_results_push(out, &result) != 0)
                rc = mm_fail(&owned_error, "cannot append MattermostPersonalToken result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&servers);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static mm_patterns mm_compiled;
static const char *const mm_keywords[] = {"mattermost"};
static const br_detector mm_detector = {
    .type = 174, .version = 0, .name = "MattermostPersonalToken", .custom_name = "",
    .description = "Mattermost is an open-source, self-hostable online chat service with file sharing, search, and integrations. Mattermost Personal Tokens can be used to authenticate API requests to a Mattermost server.",
    .keywords = mm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &mm_compiled, .scan = mm_scan,
};

int br_mattermostpersonaltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mm_fail(error, "invalid MattermostPersonalToken detector output");
    *out = NULL;
    if (!mm_compiled.key && br_regex_compile_prefixed(mm_keywords, 1,
            "\\b([a-z0-9]{26})\\b", &mm_compiled.key, error) != 0)
        return -1;
    /* Preserve the unbounded label and the unescaped dots in the host suffix. */
    if (!mm_compiled.server && br_regex_compile_prefixed(mm_keywords, 1,
            "\\b([A-Za-z0-9-_]{1,}.cloud.mattermost.com)\\b", &mm_compiled.server, error) != 0)
        return -1;
    *out = &mm_detector;
    return 0;
}
