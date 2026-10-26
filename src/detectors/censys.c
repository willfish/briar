/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/censys/censys.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *username; } censys_patterns;

static int censys_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int censys_verify(const br_scan_ctx *ctx, br_slice token, br_slice username,
                         br_result *result, char **error)
{
    char *auth = NULL;
    if (br_http_basic_auth(username, token, &auth, error) != 0) {
        free(auth);
        return -1; /* The shared provider-owned Basic allocator can return +1. */
    }
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://search.censys.io/api/v1/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 524,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1's one nonzero send domain
     * also conflates adapter allocation/setup failures, an explicit partial
     * gap. Never infer constructor/resource identity from the error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without draining. ABI1 eagerly releases
     * each request and may already have buffered the body. Body errors ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return 0;
}

static int censys_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return censys_fail(error, "invalid or uninitialized Censys scan");
    const censys_patterns *patterns = detector->state;
    if (!patterns->token || !patterns->username) return censys_fail(error, "uninitialized Censys patterns");
    size_t original_len = out->len;
    br_captures tokens = {0}, usernames = {0};
    int rc = br_captures_find(patterns->token, input, &tokens, false, error);
    if (rc == 0) rc = br_captures_find(patterns->username, input, &usernames, false, error);
    /* Independent FindAll scans, retaining occurrences and their duplicates.
     * TrimSpace is a no-op; username syntax is NOT a UUID/hex/shape check. */
    for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
        for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
            /* With fixed method/URL and ASCII captures, nil context is the
             * reachable constructor failure. Source skips this product. */
            if (verify && !ctx) continue;
            br_slice token = br_captures_at(&tokens, t), username = br_captures_at(&usernames, u);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, token, "token", username, "username", (br_slice){0}) != 0)
                rc = censys_fail(error, "out of memory creating Censys result");
            else if (verify && censys_verify(ctx, token, username, &result, error) != 0) rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = censys_fail(error, "out of memory appending Censys result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&usernames);
    return rc == 0 ? 0 : -1;
}

static censys_patterns patterns;
static const char *const censys_keywords[] = {"censys"};
static const br_detector censys_detector = {
    .type = 524, .version = 0, .name = "Censys", .custom_name = "",
    .description = "Censys is a search engine that enables researchers to ask questions about the hosts and networks "
                   "that compose the Internet. Censys API keys can be used to access and query this data.",
    .keywords = censys_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = censys_scan,
};

int br_censys_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return censys_fail(error, "invalid Censys detector output");
    *out = NULL;
    if (!patterns.token && br_regex_compile_prefixed(censys_keywords, 1, "\\b([a-zA-Z0-9]{32})\\b", &patterns.token, error) != 0)
        return -1;
    if (!patterns.username && br_regex_compile_prefixed(censys_keywords, 1, "\\b([a-z0-9-]{36})\\b", &patterns.username, error) != 0)
        return -1;
    *out = &censys_detector;
    return 0;
}
