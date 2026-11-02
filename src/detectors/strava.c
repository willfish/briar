/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/strava/strava.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *token; } strava_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_rest(const char *rest, br_regex **out, char **error)
{
    static const char *const keywords[] = {"strava"};
    char *prefix = NULL;
    if (br_prefix_regex(keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate Strava prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "Strava pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate Strava pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static int scan_strava(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Strava scan");
    const strava_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures ids = {0}, tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->token, input, &tokens, false, &owned_error);
    /* Secret and refresh-token patterns are identical, so one find supplies both lists. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t s = 0; !rc && s < tokens.len; ++s) {
            for (size_t k = 0; !rc && k < tokens.len; ++k) {
                br_result result = {0};
                br_slice id = br_captures_at(&ids, i);
                br_slice secret = br_captures_at(&tokens, s);
                br_slice refresh = br_captures_at(&tokens, k);
                if (id.len != 5 || secret.len != 40 || refresh.len != 40 ||
                    br_finding_pair_bytes(&result, detector->type, id, "id", secret, "secret",
                                          (br_slice){0}) != 0)
                    rc = fail(&owned_error, "cannot create Strava result");
                if (!rc && verify) {
                    char body[160];
                    int n = snprintf(body, sizeof(body),
                                     "grant_type=refresh_token&client_id=%.*s&client_secret=%.*s&refresh_token=%.*s",
                                     5, id.data, 40, secret.data, 40, refresh.data);
                    if (n < 0 || (size_t)n >= sizeof(body)) {
                        br_result_clear(&result);
                        rc = fail(&owned_error, "cannot build Strava body");
                        break;
                    }
                    /* Body exists before NewRequestWithContext. Nil context skips this triple. */
                    if (!ctx) {
                        br_result_clear(&result);
                        continue;
                    }
                    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
                    const br_http_request request = {
                        .method = "POST", .url = "https://www.strava.com/oauth/token",
                        .headers = headers, .nheaders = 1,
                        .body = {(const unsigned char *)body, (size_t)n},
                        .profile = BR_HTTP_SANE, .detector_type = detector->type,
                    };
                    br_http_response response = {0};
                    char *send_error = NULL;
                    if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                        response.status >= 200 && response.status < 300)
                        result.verified = true;
                    br_http_release(ctx, &response);
                    free(send_error);
                }
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned_error, "cannot append Strava result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static strava_patterns patterns;
static const char *const keywords[] = {"strava"};
static br_detector strava = {
    .type = 476, .version = 0, .name = "Strava", .custom_name = "",
    .description = "An workout app, Oauth API keys can potentially be used to access user workout data",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_strava,
};

int br_strava_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Strava detector output");
    *out = NULL;
    if (!patterns.id && compile_rest("\\b([0-9]{5})\\b", &patterns.id, error) != 0) return -1;
    if (!patterns.token && compile_rest("\\b([0-9a-z]{40})\\b", &patterns.token, error) != 0)
        return -1;
    *out = &strava;
    return 0;
}
